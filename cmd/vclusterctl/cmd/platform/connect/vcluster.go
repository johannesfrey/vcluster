package connect

import (
	"context"
	"fmt"

	"github.com/loft-sh/log"
	"github.com/loft-sh/vcluster/pkg/cli"
	"github.com/loft-sh/vcluster/pkg/cli/completion"
	"github.com/loft-sh/vcluster/pkg/cli/flags"
	"github.com/loft-sh/vcluster/pkg/cli/util"
	"github.com/loft-sh/vcluster/pkg/upgrade"
	"github.com/spf13/cobra"
)

// VClusterCmd holds the cmd flags
type VClusterCmd struct {
	Log log.Logger
	*flags.GlobalFlags
	cli.ConnectOptions
}

// newVClusterCmd creates a new command
func newVClusterCmd(globalFlags *flags.GlobalFlags) *cobra.Command {
	cmd := &VClusterCmd{
		GlobalFlags: globalFlags,
		Log:         log.GetInstance(),
	}

	useLine, nameValidator := util.NamedPositionalArgsValidator(true, false, "VCLUSTER_NAME")

	cobraCmd := &cobra.Command{
		Use:   "vcluster" + useLine,
		Short: "Connect to a virtual cluster",
		Long: `#########################################################################
################## vcluster platform connect vcluster ###################
#########################################################################
Connect to a virtual cluster

Example:
vcluster platform connect vcluster test --namespace test
# Open a new bash with the vcluster KUBECONFIG defined
vcluster platform connect vcluster test -n test -- bash
vcluster platform connect vcluster test -n test -- kubectl get ns
#########################################################################
	`,
		Args:              nameValidator,
		ValidArgsFunction: completion.NewValidVClusterNameFunc(globalFlags),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			// Check for newer version
			upgrade.PrintNewerVersionWarning()

			return cmd.Run(cobraCmd.Context(), args)
		},
	}

	cobraCmd.Flags().StringVar(&cmd.KubeConfigContextName, "kube-config-context-name", "", "If set, will override the context name of the generated virtual cluster kube config with this name")
	cobraCmd.Flags().StringVar(&cmd.KubeConfig, "kube-config", "./kubeconfig.yaml", "Writes the created kube config to this file")
	cobraCmd.Flags().BoolVar(&cmd.UpdateCurrent, "update-current", true, "If true updates the current kube config")
	cobraCmd.Flags().BoolVar(&cmd.Print, "print", false, "When enabled prints the context to stdout")
	cobraCmd.Flags().StringVar(&cmd.PodName, "pod", "", "The pod to connect to")
	cobraCmd.Flags().StringVar(&cmd.Server, "server", "", "The server to connect to")
	cobraCmd.Flags().IntVar(&cmd.LocalPort, "local-port", 0, "The local port to forward the virtual cluster to. If empty, vCluster will use a random unused port")
	cobraCmd.Flags().StringVar(&cmd.Address, "address", "", "The local address to start port forwarding under")
	cobraCmd.Flags().StringVar(&cmd.ServiceAccount, "service-account", "", "If specified, vCluster will create a service account token to connect to the virtual cluster instead of using the default client cert / key. Service account must exist and can be used as namespace/name.")
	cobraCmd.Flags().StringVar(&cmd.ServiceAccountClusterRole, "cluster-role", "", "If specified, vCluster will create the service account if it does not exist and also add a cluster role binding for the given cluster role to it. Requires --service-account to be set")
	cobraCmd.Flags().IntVar(&cmd.ServiceAccountExpiration, "token-expiration", 0, "If specified, vCluster will create the service account token for the given duration in seconds. Defaults to eternal")
	cobraCmd.Flags().BoolVar(&cmd.Insecure, "insecure", false, "If specified, vCluster will create the kube config with insecure-skip-tls-verify")
	cobraCmd.Flags().BoolVar(&cmd.BackgroundProxy, "background-proxy", false, "If specified, vCluster will create the background proxy in docker [its mainly used for vclusters with no nodeport service.]")

	// platform
	cobraCmd.Flags().StringVar(&cmd.Project, "project", "", "The platform project the vCluster is in")

	// deprecated
	_ = cobraCmd.Flags().MarkDeprecated("kube-config", fmt.Sprintf("please use %q to write the kubeconfig of the virtual cluster to stdout.", "vcluster connect --print"))
	_ = cobraCmd.Flags().MarkDeprecated("kube-config-context-name", fmt.Sprintf("please use %q to write the kubeconfig of the virtual cluster to stdout.", "vcluster connect --print"))
	_ = cobraCmd.Flags().MarkDeprecated("update-current", fmt.Sprintf("please use %q to write the kubeconfig of the virtual cluster to stdout.", "vcluster connect --print"))

	return cobraCmd
}

// Run executes the functionality
func (cmd *VClusterCmd) Run(ctx context.Context, args []string) error {
	vClusterName := ""
	if len(args) > 0 {
		vClusterName = args[0]
	}

	// validate flags
	err := cmd.validateFlags()
	if err != nil {
		return err
	}

	return cli.ConnectPlatform(ctx, &cmd.ConnectOptions, cmd.GlobalFlags, vClusterName, args[1:], cmd.Log)
}

func (cmd *VClusterCmd) validateFlags() error {
	if cmd.ServiceAccountClusterRole != "" && cmd.ServiceAccount == "" {
		return fmt.Errorf("expected --service-account to be defined as well")
	}

	return nil
}
