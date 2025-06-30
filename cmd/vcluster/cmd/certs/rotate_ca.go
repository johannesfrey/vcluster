package certs

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/loft-sh/log"
	"github.com/loft-sh/vcluster/pkg/certs"
	"github.com/loft-sh/vcluster/pkg/config"
	"github.com/loft-sh/vcluster/pkg/constants"
	"github.com/loft-sh/vcluster/pkg/lifecycle"
	"github.com/loft-sh/vcluster/pkg/pro"
	"github.com/loft-sh/vcluster/pkg/setup"
	"github.com/loft-sh/vcluster/pkg/util/servicecidr"
	"github.com/spf13/cobra"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type rotateCACmd struct {
	Path           string
	ValidityPeriod string
	log            log.Logger
}

func rotateCA() *cobra.Command {
	cmd := &rotateCACmd{
		log: log.GetInstance(),
	}

	cobraCmd := &cobra.Command{
		Use:   "rotate-ca",
		Short: "Rotates the CA certificate",
		Args:  cobra.NoArgs,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return cmd.Run(cobraCmd.Context())
		}}

	cobraCmd.Flags().StringVar(&cmd.ValidityPeriod, "validity-period", "", "The validity period of the certificates")
	cobraCmd.Flags().StringVar(&cmd.Path, "path", "", "Path to the directory containing new CA certificate files (must be named ca.crt and ca.key)")

	return cobraCmd
}

func (cmd *rotateCACmd) Run(ctx context.Context) error {
	vConfig, err := config.ParseConfig(constants.DefaultVClusterConfigLocation, os.Getenv("VCLUSTER_NAME"), nil)
	if err != nil {
		return err
	}

	vConfig.ControlPlaneConfig, vConfig.ControlPlaneNamespace, vConfig.ControlPlaneService, vConfig.WorkloadConfig, vConfig.WorkloadNamespace, vConfig.WorkloadService, err = pro.GetRemoteClient(vConfig)
	if err != nil {
		return err
	}

	if err := setup.InitClients(vConfig); err != nil {
		return err
	}

	serviceCIDR, err := servicecidr.GetServiceCIDR(ctx, &vConfig.Config, vConfig.WorkloadClient, vConfig.WorkloadService, vConfig.WorkloadNamespace)
	if err != nil {
		return fmt.Errorf("getting service cidr: %w", err)
	}

	kubeadmConfig, err := setup.GenerateInitKubeadmConfig(ctx, serviceCIDR, constants.PKIDir, vConfig)
	if err != nil {
		return fmt.Errorf("generating kubeadm config: %w", err)
	}

	if cmd.ValidityPeriod != "" && cmd.Path == "" {
		duration, err := time.ParseDuration(cmd.ValidityPeriod)
		if err != nil {
			return fmt.Errorf("parsing duration format: %v", err)
		}

		if duration > time.Hour*24*365*10 {
			return fmt.Errorf("duration must not be longer than 10 years")
		}

		cmd.log.Info("Setting custom CA cert validity period")
		kubeadmConfig.CACertificateValidityPeriod = &metav1.Duration{Duration: duration}
	}

	var caCertBytes, caKeyBytes []byte
	if cmd.Path != "" {
		if !dirExists(cmd.Path) {
			return fmt.Errorf("given path %q is not a directory", cmd.Path)
		}

		caCertBytes, err = os.ReadFile(filepath.Join(cmd.Path, certs.CACertName))
		if err != nil {
			return fmt.Errorf("reading ca.crt: %w", err)
		}

		caKeyBytes, err = os.ReadFile(filepath.Join(cmd.Path, certs.CAKeyName))
		if err != nil {
			return fmt.Errorf("reading ca.key: %w", err)
		}

		_, err = tls.X509KeyPair(caCertBytes, caKeyBytes)
		if err != nil {
			return fmt.Errorf("invalid cert/key pair: %w", err)
		}
	}

	// TODO(johannesfrey): Make backup before removing
	cmd.log.Info("Removing previous PKI dir")
	if err := os.RemoveAll(constants.PKIDir); err != nil {
		return fmt.Errorf("removing PKI directory: %w", err)
	}

	// The tls.LoadX509KeyPair above ensures that both are valid x509 files.
	// So let's copy them to the PKI dir in order for kubeadm to take over upon restart.
	if len(caCertBytes) > 0 && len(caKeyBytes) > 0 {
		cmd.log.Info("Writing custom CA cert and key files to PKI dir")
		if err := os.MkdirAll(constants.PKIDir, 0755); err != nil {
			return fmt.Errorf("creating PKI directory: %w", err)
		}
		if err := os.WriteFile(filepath.Join(constants.PKIDir, certs.CACertName), caCertBytes, 0666); err != nil {
			return fmt.Errorf("writing ca.crt: %w", err)
		}
		if err := os.WriteFile(filepath.Join(constants.PKIDir, certs.CAKeyName), caKeyBytes, 0600); err != nil {
			return fmt.Errorf("writing ca.key: %w", err)
		}
	}

	// Delete the secret so that it's recreated upon restart.
	cmd.log.Info("Deleting cert secret")
	err = vConfig.ControlPlaneClient.CoreV1().Secrets(vConfig.ControlPlaneNamespace).Delete(ctx, certs.CertSecretName(vConfig.Name), metav1.DeleteOptions{})
	if err != nil && !kerrors.IsNotFound(err) {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(vConfig.ControlPlaneConfig)
	if err != nil {
		return err
	}

	return lifecycle.DeletePods(ctx, kubeClient, "app=vcluster,release="+vConfig.Name, vConfig.ControlPlaneNamespace)
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && info.IsDir()
}
