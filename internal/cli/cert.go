package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/certificate"
)

func newCertCommand(env environment) *cobra.Command {
	command := &cobra.Command{
		Use:   "cert",
		Short: "Manage distribution certificates",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newCertCreateCommand(env))
	return command
}

func newCertCreateCommand(env environment) *cobra.Command {
	var execute bool
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a distribution certificate and save its identity to the vaults",
		Long: `Generates a private key, has App Store Connect issue an Apple Distribution
certificate for it, and saves the certificate, key, and a .p12 password to every
configured vault. The key never leaves this machine except into those vaults.

Without --execute, prints what it would do and changes nothing.`,
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
			portal, err := env.portal(cfg)
			if err != nil {
				return err
			}
			plan, err := certificate.Prepare(cmd.Context(), portal, vaults, cfg.Manifest.Team)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !execute {
				return renderCertPlan(out, plan)
			}
			created, err := certificate.Create(cmd.Context(), portal, vaults, env.recovery(), cfg.Manifest.Team)
			if created.Certificate.ID != "" {
				if renderErr := renderCertCreated(out, created); renderErr != nil && err == nil {
					err = renderErr
				}
			}
			if err != nil {
				return err
			}
			if len(created.Failures) > 0 {
				return &exitError{code: 1, message: "the identity was not saved to every vault"}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&execute, "execute", false, "create the certificate")
	return command
}

func renderCertPlan(out io.Writer, plan certificate.Plan) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Plan: create an Apple Distribution certificate for team %s\n", plan.Team)
	builder.WriteString("\nExisting distribution certificates\n")
	if len(plan.Existing) == 0 {
		builder.WriteString("  none\n")
	} else {
		table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "  ID\tNAME\tEXPIRES\tIN VAULT")
		for _, existing := range plan.Existing {
			held := "no"
			if len(existing.HeldBy) > 0 {
				held = strings.Join(existing.HeldBy, ", ")
			}
			fmt.Fprintf(table, "  %s\t%s\t%s\t%s\n", existing.Certificate.ID, existing.Certificate.Name, date(existing.Certificate.ExpiresAt), held)
		}
		table.Flush()
	}
	builder.WriteString("\nThe new identity will be saved to\n")
	for _, name := range plan.Vaults {
		fmt.Fprintf(&builder, "  %s\n", name)
	}
	builder.WriteString("\nApple limits how many distribution certificates a team can have and emails the team about each new one.\n")
	builder.WriteString("Run again with --execute to create it.\n")
	return writeTrimmed(out, builder.String())
}

func renderCertCreated(out io.Writer, created certificate.Created) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Created distribution certificate %s (serial %s, expires %s)\n", created.Certificate.ID, created.Certificate.SerialNumber, date(created.Certificate.ExpiresAt))
	if created.Fingerprint != "" {
		fmt.Fprintf(&builder, "SHA-1 fingerprint %s\n", created.Fingerprint)
	}
	if len(created.SavedTo) > 0 {
		builder.WriteString("\nSaved the identity to\n")
		for _, name := range created.SavedTo {
			fmt.Fprintf(&builder, "  %s\n", name)
		}
	}
	if len(created.Failures) > 0 {
		builder.WriteString("\nCould not save it to\n")
		for _, failure := range created.Failures {
			fmt.Fprintf(&builder, "  %s: %v\n", failure.Vault, failure.Err)
		}
	}
	if created.Recovery != "" {
		fmt.Fprintf(&builder, "\nNo configured vault saved it, so it is in %s. Move it into a vault before it is lost.\n", created.Recovery)
	}
	builder.WriteString("\nNext: renew the profiles with the new certificate.\n")
	return writeTrimmed(out, builder.String())
}
