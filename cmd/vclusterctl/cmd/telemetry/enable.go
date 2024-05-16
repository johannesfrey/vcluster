package telemetry

import (
	"github.com/loft-sh/log"
	"github.com/loft-sh/vcluster/pkg/cli/config"
	"github.com/spf13/cobra"
)

type EnableCmd struct {
	log log.Logger
}

func enable() *cobra.Command {
	cmd := &EnableCmd{
		log: log.GetInstance(),
	}

	cobraCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enables collection of anonymized vcluster telemetry",
		Long: `
#######################################################
############### vcluster telemetry enable #############
#######################################################
Enables collection of anonymized vcluster telemetry

More information about the collected telmetry is in the
docs: https://www.vcluster.com/docs/advanced-topics/telemetry

#######################################################
	`,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return cmd.Run(cobraCmd)
		}}

	return cobraCmd
}

func (cmd *EnableCmd) Run(*cobra.Command) error {
	c := config.Read(cmd.log)
	c.TelemetryDisabled = false
	return config.Write(c)
}
