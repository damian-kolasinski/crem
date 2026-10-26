package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
)

// exitNeedsAction is the exit code of `status --check` when signing needs action.
const exitNeedsAction = 3

func newStatusCommand(env environment) *cobra.Command {
	var asJSON, check bool
	var expiryDays int
	command := &cobra.Command{
		Use:   "status",
		Short: "Report certificates, expected profiles, findings, and cleanup candidates (read-only)",
		Long: `Compares the team's certificates and provisioning profiles in App Store Connect
with what crem.yaml expects, and reports what needs action. It changes nothing.

With --check, exits with status 3 when anything needs action, for scheduled CI jobs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if expiryDays <= 0 {
				return &exitError{code: 2, message: "--expiry-days must be positive"}
			}
			cfg, err := loadConfig(cmd, env)
			if err != nil {
				return err
			}
			portal, err := env.portal(cfg)
			if err != nil {
				return err
			}
			vaults, err := env.vaults(cfg)
			if err != nil {
				return err
			}
			var readers []status.Vault
			for _, store := range vaults {
				readers = append(readers, store)
			}
			policy := signing.Policy{Now: env.now(), ExpiryWindow: time.Duration(expiryDays) * 24 * time.Hour}
			result, err := status.Check(cmd.Context(), portal, readers, cfg.Manifest, policy)
			if err != nil {
				return err
			}
			for _, vaultError := range result.VaultErrors {
				fmt.Fprintf(cmd.ErrOrStderr(), "crem: warning: cannot read vault %v\n", vaultError)
			}
			report := result.Report
			if asJSON {
				err = renderStatusJSON(cmd.OutOrStdout(), report)
			} else {
				err = renderStatus(cmd.OutOrStdout(), report)
			}
			if err != nil {
				return err
			}
			if check && report.NeedsAction() {
				return &exitError{code: exitNeedsAction}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "print a JSON report")
	command.Flags().BoolVar(&check, "check", false, "exit with status 3 when anything needs action")
	command.Flags().IntVar(&expiryDays, "expiry-days", 45, "renew certificates and profiles that expire within this many days")
	return command
}
