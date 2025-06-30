package certs

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loft-sh/log"
	"github.com/loft-sh/vcluster/pkg/certs"
	"github.com/loft-sh/vcluster/pkg/cli/find"
	"github.com/loft-sh/vcluster/pkg/cli/flags"
	"github.com/loft-sh/vcluster/pkg/lifecycle"
	"github.com/loft-sh/vcluster/pkg/util/podhelper"
	"k8s.io/client-go/kubernetes"
)

func Rotate(ctx context.Context, vClusterName string, globalFlags *flags.GlobalFlags, validityPeriod string, log log.Logger) error {
	vCluster, err := find.GetVCluster(ctx, globalFlags.Context, vClusterName, globalFlags.Namespace, log)
	if err != nil {
		return err
	}

	// TODO(johannesfrey): Add min version check

	kubeConfig, err := vCluster.ClientFactory.ClientConfig()
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	// pause the vCluster
	log.Infof("Pausing vCluster %s", vCluster.Name)
	if err := lifecycle.PauseVCluster(ctx, kubeClient, vCluster.Name, vCluster.Namespace, true, log); err != nil {
		return err
	}

	// try to scale up the vCluster again
	defer func() {
		log.Infof("Resuming vCluster %s after it was paused", vCluster.Name)
		err = lifecycle.ResumeVCluster(ctx, kubeClient, vCluster.Name, vCluster.Namespace, true, log)
		if err != nil {
			log.Warnf("Error resuming vCluster %s: %v", vCluster.Name, err)
		}
	}()

	period := "8760h" // 365 days × 24 hours = 1 year
	if validityPeriod != "" {
		period = validityPeriod
	}

	return podhelper.RunPod(ctx, "certs-rotate", kubeClient, []string{"sh", "-c", "/vcluster certs rotate --validity-period=" + period}, vCluster, log)
}

func RotateCA(ctx context.Context, vClusterName string, globalFlags *flags.GlobalFlags, path, validityPeriod string, log log.Logger) error {
	var (
		caCertBytes, caKeyBytes []byte
		err                     error
	)
	if path != "" {
		if !dirExists(path) {
			return fmt.Errorf("given path %q is not a directory", path)
		}

		caCertBytes, err = os.ReadFile(filepath.Join(path, certs.CACertName))
		if err != nil {
			return fmt.Errorf("reading ca.crt: %w", err)
		}

		caKeyBytes, err = os.ReadFile(filepath.Join(path, certs.CAKeyName))
		if err != nil {
			return fmt.Errorf("reading ca.key: %w", err)
		}

		_, err = tls.X509KeyPair(caCertBytes, caKeyBytes)
		if err != nil {
			return fmt.Errorf("invalid cert/key pair: %w", err)
		}
	}

	vCluster, err := find.GetVCluster(ctx, globalFlags.Context, vClusterName, globalFlags.Namespace, log)
	if err != nil {
		return err
	}

	// TODO(johannesfrey): Add min version check

	kubeConfig, err := vCluster.ClientFactory.ClientConfig()
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	// pause the vCluster
	log.Infof("Pausing vCluster %s", vCluster.Name)
	if err := lifecycle.PauseVCluster(ctx, kubeClient, vCluster.Name, vCluster.Namespace, true, log); err != nil {
		return err
	}

	// try to scale up the vCluster again
	defer func() {
		log.Infof("Resuming vCluster %s after it was paused", vCluster.Name)
		err = lifecycle.ResumeVCluster(ctx, kubeClient, vCluster.Name, vCluster.Namespace, true, log)
		if err != nil {
			log.Warnf("Error resuming vCluster %s: %v", vCluster.Name, err)
		}
	}()

	period := "87600h" // 365 days × 24 hours * 10 = 10 years
	if validityPeriod != "" {
		period = validityPeriod
	}

	cmd := fmt.Sprintf(`
tmpdir=$(mktemp -d) &&
echo %q | base64 -d > "$tmpdir/ca.crt" &&
echo %q | base64 -d > "$tmpdir/ca.key" &&
/vcluster certs rotate-ca --validity-period=%s --path="$tmpdir" && rm -rf "$tmpdir"`,
		base64.StdEncoding.EncodeToString(caCertBytes),
		base64.StdEncoding.EncodeToString(caKeyBytes),
		period)

	return podhelper.RunPod(ctx, "certs-rotate", kubeClient, []string{"sh", "-c", cmd}, vCluster, log)
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && info.IsDir()
}
