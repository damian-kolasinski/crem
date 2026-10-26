package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/registration"
)

func newAppsCommand(env environment) *cobra.Command {
	command := &cobra.Command{
		Use:   "apps",
		Short: "Manage the bundle IDs crem.yaml expects",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newAppsRegisterCommand(env))
	return command
}

func newAppsRegisterCommand(env environment) *cobra.Command {
	var execute bool
	var bundleIDs []string
	var capabilitiesFrom string
	command := &cobra.Command{
		Use:   "register",
		Short: "Register the bundle IDs crem.yaml expects that the team lacks",
		Long: `Registers every bundle ID crem.yaml expects that is not registered yet, or only
those given with --bundle-id, and copies capabilities onto it: from --capabilities-from,
or else from the same app or extension in another environment. Capabilities that use
containers, such as App Groups or iCloud, still need their identifiers assigned in the
developer portal, and the App Store Connect app record is created there too.

Without --execute, prints what it would register and changes nothing.`,
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
			plan, err := registration.Prepare(cmd.Context(), portal, cfg.Manifest, registration.Request{BundleIDs: bundleIDs, CapabilitiesFrom: capabilitiesFrom})
			if err != nil {
				return err
			}
			var builder strings.Builder
			if len(plan.Registrations) == 0 {
				fmt.Fprintf(&builder, "Every bundle ID crem.yaml expects is registered (%d).\n", plan.Registered)
				return writeTrimmed(cmd.OutOrStdout(), builder.String())
			}
			if !execute {
				builder.WriteString("Plan: register\n")
				for _, item := range plan.Registrations {
					if item.AlreadyRegistered {
						fmt.Fprintf(&builder, "  %s  registered; add %s\n", item.Target.BundleID, describeCapabilities(item))
					} else {
						fmt.Fprintf(&builder, "  %s  %q  %s\n", item.Target.BundleID, item.Name, describeCapabilities(item))
					}
				}
				writeSetupReminder(&builder, plan.Registrations)
				builder.WriteString("\nRun again with --execute to register them.\n")
				return writeTrimmed(cmd.OutOrStdout(), builder.String())
			}
			done, err := registration.Execute(cmd.Context(), portal, plan)
			var registered []registration.Registration
			for _, result := range done {
				registered = append(registered, result.Registration)
				verb := "Registered"
				if result.Registration.AlreadyRegistered {
					verb = "Completed"
				}
				fmt.Fprintf(&builder, "%s %s  %s\n", verb, result.Registration.Target.BundleID, describeCapabilities(result.Registration))
				for _, capability := range slices.Sorted(maps.Keys(result.Failed)) {
					fmt.Fprintf(&builder, "  could not enable %s: %v\n", capability, result.Failed[capability])
				}
				if len(result.Failed) > 0 {
					fmt.Fprintf(&builder, "  retry with: crem apps register --bundle-id %s --execute\n", result.Registration.Target.BundleID)
				}
			}
			writeSetupReminder(&builder, registered)
			if len(done) > 0 {
				builder.WriteString("\nNext: create the App Store Connect app record if this is a new app, then renew the profiles.\n")
			}
			if writeErr := writeTrimmed(cmd.OutOrStdout(), builder.String()); writeErr != nil && err == nil {
				err = writeErr
			}
			return err
		},
	}
	command.Flags().BoolVar(&execute, "execute", false, "register the bundle IDs")
	command.Flags().StringSliceVar(&bundleIDs, "bundle-id", nil, "only these bundle IDs")
	command.Flags().StringVar(&capabilitiesFrom, "capabilities-from", "", "copy capabilities from this registered bundle ID")
	return command
}

func describeCapabilities(item registration.Registration) string {
	if item.CapabilitiesFrom == "" {
		return "no capabilities copied"
	}
	var types []string
	for _, capability := range item.Capabilities {
		types = append(types, capability.Type)
	}
	return fmt.Sprintf("capabilities from %s: %s", item.CapabilitiesFrom, strings.Join(types, ", "))
}

func writeSetupReminder(builder *strings.Builder, registrations []registration.Registration) {
	var needs []string
	for _, item := range registrations {
		for _, capability := range item.Capabilities {
			if setup := capability.NeedsPortalSetup(); setup != "" {
				needs = append(needs, fmt.Sprintf("%s: %s", item.Target.BundleID, setup))
			}
		}
	}
	if len(needs) > 0 {
		builder.WriteString("\nAssign these in the developer portal afterwards, then renew the profiles:\n")
		for _, need := range needs {
			fmt.Fprintf(builder, "  %s\n", need)
		}
	}
}
