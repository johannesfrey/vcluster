package config

import (
	"strings"

	"github.com/ghodss/yaml"
	"github.com/loft-sh/log"
)

type (
	LegacyConfig struct {
		Experimental map[string]any
		SleepMode    map[string]any `yaml:"sleepMode,omitempty"`
	}
)

func ConfigStructureWarning(logger log.Logger, currentValues []byte, advisors map[string]func() string) string {
	exp := &LegacyConfig{}
	if err := yaml.Unmarshal(currentValues, exp); err != nil {
		logger.Warn(err)
		return ""
	}

	var advice []string
	for k := range exp.Experimental {
		if advisor, ok := advisors[k]; ok {
			if warning := advisor(); warning != "" {
				advice = append(advice, warning)
			}
		}
	}

	if len(exp.SleepMode) != 0 {
		if advisor, ok := advisors["sleepMode"]; ok {
			if warning := advisor(); warning != "" {
				return warning
			}
		}

	}

	if len(advice) == 0 {
		return ""
	}

	expWarning := "An experimental feature you were using has been promoted! 🎉 See below on tips to update."
	return strings.Join(append([]string{expWarning}, advice...), "\n")
}
