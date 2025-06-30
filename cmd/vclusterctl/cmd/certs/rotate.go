package certs

import (
	"github.com/loft-sh/log"
	"github.com/loft-sh/vcluster/pkg/cli/certs"
	"github.com/loft-sh/vcluster/pkg/cli/completion"
	"github.com/loft-sh/vcluster/pkg/cli/flags"
	"github.com/loft-sh/vcluster/pkg/cli/util"
	"github.com/spf13/cobra"
)

type rotateCmd struct {
	*flags.GlobalFlags

	ValidityPeriod string
	log            log.Logger
}

func rotate(globalFlags *flags.GlobalFlags) *cobra.Command {
	cmd := &rotateCmd{
		GlobalFlags: globalFlags,
		log:         log.GetInstance(),
	}

	useLine, nameValidator := util.NamedPositionalArgsValidator(true, false, "VCLUSTER_NAME")
	cobraCmd := &cobra.Command{
		Use:   "rotate" + useLine,
		Short: "Rotates control-plane client and server certs",
		Long: `##############################################################
################### vcluster certs rotate ####################
##############################################################
Rotates the control-plane client and server leaf certificates
of the given virtual cluster.

Examples:
vcluster -n test certs rotate test
##############################################################
	`,
		Args:              nameValidator,
		ValidArgsFunction: completion.NewValidVClusterNameFunc(globalFlags),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return certs.Rotate(cobraCmd.Context(), args[0], cmd.GlobalFlags, cmd.ValidityPeriod, cmd.log)
		}}

	cobraCmd.Flags().StringVar(&cmd.ValidityPeriod, "validity-period", "", "The validity period of the certificates")
	_ = cobraCmd.Flags().MarkHidden("validity-period")

	return cobraCmd
}

type rotateCACmd struct {
	*flags.GlobalFlags

	ValidityPeriod string
	Path           string
	log            log.Logger
}

func rotateCA(globalFlags *flags.GlobalFlags) *cobra.Command {
	cmd := &rotateCACmd{
		GlobalFlags: globalFlags,
		log:         log.GetInstance(),
	}

	useLine, nameValidator := util.NamedPositionalArgsValidator(true, false, "VCLUSTER_NAME")
	cobraCmd := &cobra.Command{
		Use:   "rotate-ca" + useLine,
		Short: "Rotates the CA certificate",
		Long: `##############################################################
################## vcluster certs rotate-ca ##################
##############################################################
Rotates the CA certificates of the given virtual cluster using
the given CA certificates.
If the ca.crt file is a bundle containing multiple certificates
the new CA cert must be the first one in the bundle.

Examples:
vcluster certs rotate-ca test --path /tmp/ca-certs
##############################################################
	`,
		Args:              nameValidator,
		ValidArgsFunction: completion.NewValidVClusterNameFunc(globalFlags),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return certs.RotateCA(cobraCmd.Context(), args[0], cmd.GlobalFlags, cmd.Path, cmd.ValidityPeriod, cmd.log)
		}}

	cobraCmd.Flags().StringVar(&cmd.Path, "path", "", "Path to the directory containing new CA certificate files (must be named ca.crt and ca.key)")
	cobraCmd.Flags().StringVar(&cmd.ValidityPeriod, "validity-period", "", "The validity period of the CA certificate")
	_ = cobraCmd.Flags().MarkHidden("validity-period")

	return cobraCmd
}
