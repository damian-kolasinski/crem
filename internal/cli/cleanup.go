package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/cleanup"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
)

func newCleanupCommand(env environment) *cobra.Command {
	var execute, revokeCertificates bool
	command := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete dead profiles and, on request, revoke certificates nothing signs with",
		Long: `Deletes the dead provisioning profiles (expired, invalid, or whose certificates are
gone) in the cleanup scope that no expected profile resolves to. Live leftovers are
listed but never deleted. With --revoke-certificates, also revokes distribution
certificates that no live profile uses, except the newest; installed Ad Hoc builds
signed with a revoked certificate stop launching.

Run it once CI has built successfully with the new signing. Without --execute,
prints what it would do and changes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			policy := signing.Policy{Now: env.now(), ExpiryWindow: 45 * 24 * time.Hour}
			plan, err := cleanup.Prepare(cmd.Context(), portal, readers, cfg.Manifest, policy, revokeCertificates)
			if err != nil {
				return err
			}
			for _, vaultError := range plan.VaultErrors {
				fmt.Fprintf(cmd.ErrOrStderr(), "crem: warning: cannot read vault %v\n", vaultError)
			}
			out := cmd.OutOrStdout()
			if !execute || (len(plan.Delete) == 0 && len(plan.Revoke) == 0) {
				return renderCleanupPlan(out, plan, revokeCertificates)
			}
			removed, err := cleanup.Execute(cmd.Context(), portal, plan)
			var builder strings.Builder
			fmt.Fprintf(&builder, "Deleted %d of %s\n", len(removed.Profiles), count(len(plan.Delete), "profile"))
			for _, profile := range removed.Profiles {
				fmt.Fprintf(&builder, "  %s  %s\n", profile.ID, profile.Name)
			}
			if len(plan.Revoke) > 0 {
				fmt.Fprintf(&builder, "Revoked %d of %s\n", len(removed.Certificates), count(len(plan.Revoke), "certificate"))
				for _, certificate := range removed.Certificates {
					fmt.Fprintf(&builder, "  %s  %s\n", certificate.ID, certificate.Name)
				}
			}
			if len(plan.Keep) > 0 {
				fmt.Fprintf(&builder, "Kept %s still live; run crem cleanup to list them.\n", count(len(plan.Keep), "leftover profile"))
			}
			if writeErr := writeTrimmed(out, builder.String()); writeErr != nil && err == nil {
				err = writeErr
			}
			return err
		},
	}
	command.Flags().BoolVar(&execute, "execute", false, "delete and revoke")
	command.Flags().BoolVar(&revokeCertificates, "revoke-certificates", false, "also revoke distribution certificates no live profile uses")
	return command
}

func renderCleanupPlan(out io.Writer, plan cleanup.Plan, revokeCertificates bool) error {
	var builder strings.Builder
	if len(plan.Delete) == 0 {
		builder.WriteString("No dead profiles to delete.\n")
	} else {
		fmt.Fprintf(&builder, "Plan: delete %s\n\n", count(len(plan.Delete), "dead profile"))
		writeCandidates(&builder, plan.Delete)
	}
	if len(plan.Keep) > 0 {
		fmt.Fprintf(&builder, "\nKept: %s still live, which something may use; delete them in App Store Connect if not\n\n", count(len(plan.Keep), "leftover profile"))
		writeCandidates(&builder, plan.Keep)
	}
	if len(plan.Revocable) > 0 {
		verb := "Would revoke with --revoke-certificates"
		if revokeCertificates {
			verb = "Plan: revoke (installed Ad Hoc builds signed with them stop launching)"
		}
		fmt.Fprintf(&builder, "\n%s\n", verb)
		for _, certificate := range plan.Revocable {
			fmt.Fprintf(&builder, "  %s  %s  expires %s\n", certificate.ID, certificate.Name, date(certificate.ExpiresAt))
		}
	}
	if len(plan.Delete) > 0 || len(plan.Revoke) > 0 {
		builder.WriteString("\nRun again with --execute once CI has built with the new signing.\n")
	}
	return writeTrimmed(out, builder.String())
}

func writeCandidates(builder *strings.Builder, candidates []signing.ProfileCandidate) {
	table := tabwriter.NewWriter(builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  ID\tNAME\tBUNDLE ID\tEXPIRES\tWHY")
	for _, candidate := range candidates {
		var reasons []string
		for _, reason := range candidate.Reasons {
			reasons = append(reasons, strings.ToLower(strings.ReplaceAll(string(reason), "_", " ")))
		}
		profile := candidate.Profile
		fmt.Fprintf(table, "  %s\t%s\t%s\t%s\t%s\n", profile.ID, profile.Name, profile.BundleID, date(profile.ExpiresAt), strings.Join(reasons, ", "))
	}
	table.Flush()
}
