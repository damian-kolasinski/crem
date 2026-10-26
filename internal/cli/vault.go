package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/vaultsync"
)

func newVaultCommand(env environment) *cobra.Command {
	command := &cobra.Command{
		Use:   "vault",
		Short: "Manage the vaults that keep signing identities",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newVaultSyncCommand(env))
	return command
}

func newVaultSyncCommand(env environment) *cobra.Command {
	var execute bool
	command := &cobra.Command{
		Use:   "sync",
		Short: "Copy every signing identity into every configured vault that lacks it",
		Long: `Copies each identity a configured vault holds into the configured vaults that do
not, after checking its .p12 opens with its password. Use it after adding a vault
to crem.yaml. Identities a vault already holds are never replaced.

Without --execute, prints what it would copy and changes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd, env)
			if err != nil {
				return err
			}
			vaults, err := env.vaults(cfg)
			if err != nil {
				return err
			}
			plan, err := vaultsync.Prepare(cmd.Context(), vaults, cfg.Manifest.Team)
			if err != nil {
				return err
			}
			var builder strings.Builder
			if len(plan.Copies) == 0 {
				fmt.Fprintf(&builder, "Every vault holds every identity (%d).\n", plan.InSync)
				return writeTrimmed(cmd.OutOrStdout(), builder.String())
			}
			if !execute {
				builder.WriteString("Plan: copy\n")
				for _, item := range plan.Copies {
					var to []string
					for _, store := range item.To {
						to = append(to, store.Describe())
					}
					fmt.Fprintf(&builder, "  %s from %s to %s\n", item.CertificateID, item.From[0].Describe(), strings.Join(to, ", "))
				}
				builder.WriteString("\nRun again with --execute to copy them.\n")
				return writeTrimmed(cmd.OutOrStdout(), builder.String())
			}
			results, err := vaultsync.Execute(cmd.Context(), plan, cfg.Manifest.Team)
			for _, result := range results {
				if result.AlreadyHeld {
					fmt.Fprintf(&builder, "%s already holds an identity for %s; left it in place\n", result.To, result.CertificateID)
				} else {
					fmt.Fprintf(&builder, "Copied %s to %s\n", result.CertificateID, result.To)
				}
			}
			if writeErr := writeTrimmed(cmd.OutOrStdout(), builder.String()); writeErr != nil && err == nil {
				err = writeErr
			}
			return err
		},
	}
	command.Flags().BoolVar(&execute, "execute", false, "copy the identities")
	return command
}
