// Package cli maps crem's command line onto its use cases.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/appstoreconnect"
	"github.com/damian-kolasinski/crem/internal/appstoreconnect/auth"
	"github.com/damian-kolasinski/crem/internal/appstoreconnect/jsonapi"
	"github.com/damian-kolasinski/crem/internal/certificate"
	"github.com/damian-kolasinski/crem/internal/cleanup"
	"github.com/damian-kolasinski/crem/internal/config"
	"github.com/damian-kolasinski/crem/internal/publish"
	"github.com/damian-kolasinski/crem/internal/registration"
	"github.com/damian-kolasinski/crem/internal/renewal"
	"github.com/damian-kolasinski/crem/internal/secretstore"
	"github.com/damian-kolasinski/crem/internal/status"
	"github.com/damian-kolasinski/crem/internal/vault"
	"github.com/damian-kolasinski/crem/internal/vault/local"
	"github.com/damian-kolasinski/crem/internal/vault/onepassword"
)

// Streams are the outputs a command writes to.
type Streams struct {
	Out io.Writer
	Err io.Writer
}

// environment is what commands read from the process and the providers they reach.
type environment struct {
	workingDir string
	homeDir    string
	getenv     func(string) string
	now        func() time.Time
	// portal connects to App Store Connect with the config's API key.
	portal func(config.Config) (portal, error)
	// vaults opens the config's vaults.
	vaults func(config.Config) ([]vault.Vault, error)
	// secretStores opens the config's secret stores.
	secretStores func(config.Config) ([]secretstore.Store, error)
	// recovery keeps a new certificate's key until a vault holds its identity.
	recovery func() certificate.Recovery
}

// portal is everything commands do in App Store Connect.
type portal interface {
	status.Portal
	certificate.Portal
	renewal.Portal
	publish.Portal
	cleanup.Portal
	registration.Portal
}

// exitError ends the process with a specific exit code after its message, if any, is printed.
type exitError struct {
	code    int
	message string
}

func (e *exitError) Error() string { return e.message }

// Run executes the command line and returns the process exit code.
func Run(args []string, streams Streams, version string) int {
	workingDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(streams.Err, "crem: %v\n", err)
		return 1
	}
	homeDir, _ := os.UserHomeDir()
	env := environment{workingDir: workingDir, homeDir: homeDir, getenv: os.Getenv, now: time.Now}
	env.portal = func(cfg config.Config) (portal, error) { return connect(cfg, env) }
	env.vaults = func(cfg config.Config) ([]vault.Vault, error) { return openVaults(cfg, env) }
	env.secretStores = func(cfg config.Config) ([]secretstore.Store, error) { return openSecretStores(cfg, env) }
	env.recovery = func() certificate.Recovery { return local.NewRecovery(filepath.Join(homeDir, ".crem", "recovery")) }
	return run(args, streams, version, env)
}

func run(args []string, streams Streams, version string, env environment) int {
	// An interrupt cancels in-flight requests instead of killing the process mid-operation.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root := newRootCommand(streams, version, env)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var exit *exitError
	if errors.As(err, &exit) {
		if exit.message != "" {
			fmt.Fprintf(streams.Err, "crem: %s\n", exit.message)
		}
		return exit.code
	}
	fmt.Fprintf(streams.Err, "crem: %v\n", err)
	return 1
}

func newRootCommand(streams Streams, version string, env environment) *cobra.Command {
	root := &cobra.Command{
		Use:           "crem",
		Short:         "Keep Apple code signing healthy: certificates, provisioning profiles, and CI secrets",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.PersistentFlags().String("config", "", "path to crem.yaml (default: the nearest one in this or a parent directory)")
	root.AddCommand(newStatusCommand(env), newCertCommand(env), newProfilesCommand(env), newSecretsCommand(env), newVaultCommand(env), newCleanupCommand(env), newAppsCommand(env), newConfigCommand(env))
	return root
}

func loadConfig(cmd *cobra.Command, env environment) (config.Config, error) {
	path, _ := cmd.Flags().GetString("config")
	if path == "" {
		found, err := config.Find(env.workingDir)
		if err != nil {
			return config.Config{}, err
		}
		path = found
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(env.workingDir, path)
	}
	return config.Load(path)
}

func openVaults(cfg config.Config, env environment) ([]vault.Vault, error) {
	var vaults []vault.Vault
	for _, configured := range cfg.Vaults {
		switch {
		case configured.Local != nil:
			directory, err := configured.Local.Directory(cfg.Manifest.Team, config.Environment{HomeDir: env.homeDir, ConfigDir: filepath.Dir(cfg.Path)})
			if err != nil {
				return nil, err
			}
			vaults = append(vaults, local.New(directory))
		case configured.OnePassword != nil:
			vaults = append(vaults, onepassword.New(configured.OnePassword.Vault, configured.OnePassword.Account, onepassword.CLI{}))
		}
	}
	return vaults, nil
}

func connect(cfg config.Config, env environment) (*appstoreconnect.Client, error) {
	environment := config.Environment{
		Getenv:     env.getenv,
		HomeDir:    env.homeDir,
		WorkingDir: env.workingDir,
		ConfigDir:  filepath.Dir(cfg.Path),
	}
	credentials, err := cfg.AppStoreConnect.Resolve(environment)
	if err != nil {
		return nil, err
	}
	keyData, source, err := credentials.PrivateKey(environment)
	if err != nil {
		return nil, err
	}
	key, err := auth.ParseKey(credentials.KeyID, credentials.IssuerID, keyData)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	api, err := jsonapi.New(jsonapi.DefaultBaseURL, auth.NewTokenSource(key, env.now), &http.Client{Timeout: 60 * time.Second})
	if err != nil {
		return nil, err
	}
	return appstoreconnect.New(api), nil
}
