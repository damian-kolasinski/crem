package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

type configTargetJSON struct {
	App         string              `json:"app"`
	Environment string              `json:"environment"`
	Component   string              `json:"component"`
	BundleID    string              `json:"bundleId"`
	Secret      string              `json:"secret,omitempty"`
	Profiles    []configProfileJSON `json:"profiles"`
}

type configProfileJSON struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

func newConfigCommand(env environment) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "config",
		Short: "Print what crem.yaml expects, without contacting App Store Connect",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd, env)
			if err != nil {
				return err
			}
			targets := []configTargetJSON{}
			for _, target := range cfg.Manifest.Targets {
				entry := configTargetJSON{App: target.App, Environment: target.Environment, Component: target.Component(), BundleID: target.BundleID, Secret: target.Secret, Profiles: []configProfileJSON{}}
				for _, expected := range cfg.Manifest.ExpectedProfiles() {
					if expected.Target.BundleID == target.BundleID {
						entry.Profiles = append(entry.Profiles, configProfileJSON{Kind: expected.Spec.Kind.String(), Name: expected.Name})
					}
				}
				targets = append(targets, entry)
			}
			if asJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(map[string]any{"team": cfg.Manifest.Team, "targets": targets})
			}
			var builder strings.Builder
			fmt.Fprintf(&builder, "Team %s · %s\n\n", cfg.Manifest.Team, cfg.Path)
			table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
			fmt.Fprintln(table, "  BUNDLE ID\tAPP\tENVIRONMENT\tCOMPONENT\tSECRET")
			for _, target := range targets {
				fmt.Fprintf(table, "  %s\t%s\t%s\t%s\t%s\n", target.BundleID, target.App, target.Environment, target.Component, target.Secret)
			}
			table.Flush()
			return writeTrimmed(cmd.OutOrStdout(), builder.String())
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return command
}
