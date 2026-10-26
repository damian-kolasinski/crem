package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/download"
	"github.com/damian-kolasinski/crem/internal/signing"
)

func newProfilesDownloadCommand(env environment) *cobra.Command {
	var kind, app, environmentName, output string
	var bundleIDs []string
	var install bool
	var expiryDays int
	command := &cobra.Command{
		Use:   "download",
		Short: "Download the current profiles of a kind, as a build signs with them",
		Long: `Downloads the live profile of every bundle ID crem.yaml expects for the selection,
checking each file is that profile, and writes it as <uuid>.mobileprovision. It writes
nothing unless every selected profile is live, so a build fails clearly instead of
signing with a partial set. --install writes them where Xcode looks for profiles.`,
		Example: `  crem profiles download --kind ad-hoc --app MyApp --environment Staging --install`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			profileKind, err := signing.ParseProfileKind(kind)
			if err != nil {
				return &exitError{code: 2, message: "--kind: " + err.Error()}
			}
			var destinations download.Destinations
			if output != "" {
				destinations.Outputs = append(destinations.Outputs, output)
			}
			if install {
				if env.homeDir == "" {
					return errors.New("--install needs a home directory")
				}
				destinations.Installs = append(destinations.Installs,
					filepath.Join(env.homeDir, "Library", "MobileDevice", "Provisioning Profiles"),
					filepath.Join(env.homeDir, "Library", "Developer", "Xcode", "UserData", "Provisioning Profiles"))
			}
			if len(destinations.Outputs)+len(destinations.Installs) == 0 {
				return &exitError{code: 2, message: "give --output, --install, or both"}
			}
			cfg, err := loadConfig(cmd, env)
			if err != nil {
				return err
			}
			portal, err := env.portal(cfg)
			if err != nil {
				return err
			}
			now := env.now()
			selection := download.Selection{Kind: profileKind, App: app, Environment: environmentName, BundleIDs: bundleIDs}
			downloaded, err := download.Run(cmd.Context(), portal, cfg.Manifest, selection, destinations, now)
			var builder strings.Builder
			for _, item := range downloaded {
				fmt.Fprintf(&builder, "Downloaded %s (%s, expires %s)\n", item.Expected.Name, item.Profile.ID, date(item.Profile.ExpiresAt))
				for _, path := range item.Paths {
					fmt.Fprintf(&builder, "  %s\n", path)
				}
				for _, path := range item.Replaced {
					fmt.Fprintf(&builder, "  replaced %s\n", path)
				}
				if item.Profile.ExpiresAt.Before(now.Add(time.Duration(expiryDays) * 24 * time.Hour)) {
					fmt.Fprintf(cmd.ErrOrStderr(), "crem: warning: %s expires %s; renew it soon\n", item.Expected.Name, date(item.Profile.ExpiresAt))
				}
			}
			if writeErr := writeTrimmed(cmd.OutOrStdout(), builder.String()); writeErr != nil && err == nil {
				err = writeErr
			}
			return err
		},
	}
	command.Flags().StringVar(&kind, "kind", "", "profile kind: app-store or ad-hoc (required)")
	command.Flags().StringVar(&app, "app", "", "only this app")
	command.Flags().StringVar(&environmentName, "environment", "", "only this environment")
	command.Flags().StringSliceVar(&bundleIDs, "bundle-id", nil, "only these bundle IDs")
	command.Flags().StringVar(&output, "output", "", "directory to write the profiles to")
	command.Flags().BoolVar(&install, "install", false, "also write them where Xcode looks for profiles, replacing older profiles with the same name")
	command.Flags().IntVar(&expiryDays, "expiry-days", 45, "warn about profiles that expire within this many days")
	return command
}
