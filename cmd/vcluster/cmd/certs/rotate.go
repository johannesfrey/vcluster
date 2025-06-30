package certs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/loft-sh/log"
	"github.com/loft-sh/vcluster/pkg/certs"
	"github.com/loft-sh/vcluster/pkg/config"
	"github.com/loft-sh/vcluster/pkg/constants"
	"github.com/loft-sh/vcluster/pkg/pro"
	"github.com/loft-sh/vcluster/pkg/setup"
	"github.com/loft-sh/vcluster/pkg/util/servicecidr"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeadmcerts "k8s.io/kubernetes/cmd/kubeadm/app/phases/certs"
)

var clientServerLeaves = []string{
	certs.FrontProxyClientCertName,
	certs.FrontProxyClientKeyName,
	certs.APIServerEtcdClientCertName,
	certs.APIServerEtcdClientKeyName,
	certs.APIServerKubeletClientCertName,
	certs.APIServerKubeletClientKeyName,
	certs.APIServerCertName,
	certs.APIServerKeyName,
	certs.EtcdHealthcheckClientCertName,
	certs.EtcdHealthcheckClientKeyName,
	certs.EtcdPeerCertName,
	certs.EtcdPeerKeyName,
	certs.EtcdServerCertName,
	certs.EtcdServerKeyName,
}

type rotateCmd struct {
	ValidityPeriod string
	log            log.Logger
}

func rotate() *cobra.Command {
	cmd := &rotateCmd{
		log: log.GetInstance(),
	}

	cobraCmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotates control-plane client and server certs",
		Args:  cobra.NoArgs,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return cmd.Run(cobraCmd.Context())
		}}

	cobraCmd.Flags().StringVar(&cmd.ValidityPeriod, "validity-period", "", "The validity period of the certificates")

	return cobraCmd
}

func (cmd *rotateCmd) Run(ctx context.Context) error {
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
		return fmt.Errorf("get service cidr: %w", err)
	}

	kubeadmConfig, err := setup.GenerateInitKubeadmConfig(ctx, serviceCIDR, constants.PKIDir, vConfig)
	if err != nil {
		return fmt.Errorf("generate kubeadm config: %w", err)
	}

	if cmd.ValidityPeriod != "" {
		duration, err := time.ParseDuration(cmd.ValidityPeriod)
		if err != nil {
			return fmt.Errorf("invalid duration format: %v", err)
		}

		if duration > time.Hour*24*365 {
			return fmt.Errorf("duration must not be longer than 1 year")
		}

		kubeadmConfig.CertificateValidityPeriod = &metav1.Duration{Duration: duration}
	}

	// Remove client and server leaf certs and keys so that kubeadm is able to recreate them below.
	for _, l := range clientServerLeaves {
		err = os.Remove(filepath.Join(constants.PKIDir, l))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	if err := kubeadmcerts.CreatePKIAssets(kubeadmConfig); err != nil {
		return err
	}

	if err := certs.SplitCACert(constants.PKIDir); err != nil {
		return err
	}

	// Delete the secret so that it's recreated upon restart.
	return vConfig.ControlPlaneClient.CoreV1().Secrets(vConfig.ControlPlaneNamespace).Delete(ctx, certs.CertSecretName(vConfig.Name), metav1.DeleteOptions{})
}
