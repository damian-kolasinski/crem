package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/renewal"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
)

func newProfilesCommand(env environment) *cobra.Command {
	command := &cobra.Command{
		Use:   "profiles",
		Short: "Manage provisioning profiles",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newProfilesRenewCommand(env))
	return command
}

func newProfilesRenewCommand(env environment) *cobra.Command {
	var execute bool
	var expiryDays int
	var certificateID string
	command := &cobra.Command{
		Use:   "renew",
		Short: "Create every expected profile that is missing, expiring, or signed with another certificate",
		Long: `Creates the profiles crem.yaml expects that are missing, expired, expiring, or
signed with a certificate other than the signing certificate: by default the
distribution certificate that expires last and whose identity a vault holds.
Ad Hoc profiles keep the enabled devices of the profile they replace, unless
their kind is configured with devices: all. Old profiles are left in place.

Without --execute, prints what it would do and changes nothing.`,
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
			plan, err := renewal.Prepare(cmd.Context(), portal, readers, cfg.Manifest, policy, certificateID)
			if err != nil {
				return err
			}
			for _, vaultError := range plan.VaultErrors {
				fmt.Fprintf(cmd.ErrOrStderr(), "crem: warning: cannot read vault %v\n", vaultError)
			}
			out := cmd.OutOrStdout()
			if !execute || len(plan.Items) == 0 {
				return renderRenewalPlan(out, plan, execute)
			}
			created, err := renewal.Execute(cmd.Context(), portal, plan)
			if renderErr := renderRenewalCreated(out, created, len(plan.Items)); renderErr != nil && err == nil {
				err = renderErr
			}
			return err
		},
	}
	command.Flags().BoolVar(&execute, "execute", false, "create the profiles")
	command.Flags().IntVar(&expiryDays, "expiry-days", 45, "renew profiles that expire within this many days")
	command.Flags().StringVar(&certificateID, "certificate", "", "sign with this certificate ID instead of the default")
	return command
}

func renderRenewalPlan(out io.Writer, plan renewal.Plan, execute bool) error {
	var builder strings.Builder
	certificate := plan.Certificate
	if len(plan.Items) == 0 {
		fmt.Fprintf(&builder, "Nothing to renew: every profile crem can renew is signed with %s.\n", certificate.ID)
	} else {
		fmt.Fprintf(&builder, "Plan: create %s signed with %s (%s, expires %s)\n\n", count(len(plan.Items), "profile"), certificate.ID, certificate.Name, date(certificate.ExpiresAt))
		table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "  PROFILE\tKIND\tREASON\tDEVICES\tDELETES FIRST")
		replacesLiveAdHoc := false
		for _, item := range plan.Items {
			devices := ""
			if item.Expected.Spec.Kind == signing.AdHoc {
				devices = fmt.Sprintf("%d (%s)", len(item.Devices), item.DeviceSource)
				replacesLiveAdHoc = replacesLiveAdHoc || item.Reason == signing.RenewExpiring || item.Reason == signing.RenewOtherCertificate
			}
			var removes []string
			for _, dead := range item.Removes {
				removes = append(removes, dead.ID+" (dead)")
			}
			fmt.Fprintf(table, "  %s\t%s\t%s\t%s\t%s\n", item.Expected.Name, item.Expected.Spec.Kind, item.Reason, devices, strings.Join(removes, ", "))
		}
		table.Flush()
		if replacesLiveAdHoc {
			builder.WriteString("\nCI that downloads Ad Hoc profiles by name switches to the new ones at once; push the new certificate to CI right after.\n")
		}
	}
	if len(plan.Skipped) > 0 {
		builder.WriteString("\nSkipped\n")
		table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
		for _, skip := range plan.Skipped {
			fmt.Fprintf(table, "  %s\t%s\t%s\n", skip.Expected.Name, skip.Expected.Spec.Kind, skip.Reason)
		}
		table.Flush()
	}
	if plan.UpToDate > 0 {
		fmt.Fprintf(&builder, "\n%s up to date.\n", count(plan.UpToDate, "profile"))
	}
	if len(plan.Items) > 0 && !execute {
		builder.WriteString("\nLive profiles being replaced stay in place; dead ones with the same name are deleted first.\nRun again with --execute to create the new profiles.\n")
	}
	return writeTrimmed(out, builder.String())
}

func renderRenewalCreated(out io.Writer, created []renewal.Created, planned int) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Created %d of %s\n", len(created), count(planned, "profile"))
	if len(created) > 0 {
		builder.WriteString("\n")
		table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "  PROFILE\tKIND\tID\tEXPIRES\tDELETED")
		for _, profile := range created {
			var removed []string
			for _, dead := range profile.Removed {
				removed = append(removed, dead.ID)
			}
			fmt.Fprintf(table, "  %s\t%s\t%s\t%s\t%s\n", profile.Profile.Name, profile.Item.Expected.Spec.Kind, profile.Profile.ID, date(profile.Profile.ExpiresAt), strings.Join(removed, ", "))
		}
		table.Flush()
	}
	if len(created) < planned {
		builder.WriteString("\nRun crem profiles renew --execute again to continue; it picks up the profiles still missing.\n")
	} else {
		builder.WriteString("\nNext: push the certificate and App Store profiles to CI.\n")
	}
	return writeTrimmed(out, builder.String())
}
