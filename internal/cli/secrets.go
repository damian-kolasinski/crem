package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/damian-kolasinski/crem/internal/config"
	"github.com/damian-kolasinski/crem/internal/publish"
	"github.com/damian-kolasinski/crem/internal/secretstore"
	"github.com/damian-kolasinski/crem/internal/secretstore/github"
	"github.com/damian-kolasinski/crem/internal/signing"
)

func newSecretsCommand(env environment) *cobra.Command {
	command := &cobra.Command{
		Use:   "secrets",
		Short: "Manage the secrets CI signs with",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newSecretsPushCommand(env))
	return command
}

func newSecretsPushCommand(env environment) *cobra.Command {
	var execute bool
	command := &cobra.Command{
		Use:   "push",
		Short: "Push the signing identity and the App Store profiles to CI's secret stores",
		Long: `Reads the signing certificate's identity from a vault and downloads every App
Store profile that has a secret, checks each profile is live and contains that
certificate, and writes the .p12, its password, and the profiles to every
configured secret store. It refuses unless every profile secret can be written,
since CI signs every target with the one certificate.

Without --execute, prints what it would write and changes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd, env)
			if err != nil {
				return err
			}
			if cfg.CertificateSecrets == nil {
				return errors.New("crem.yaml names no certificate.secrets")
			}
			portal, err := env.portal(cfg)
			if err != nil {
				return err
			}
			vaults, err := env.vaults(cfg)
			if err != nil {
				return err
			}
			stores, err := env.secretStores(cfg)
			if err != nil {
				return err
			}
			names := publish.CertificateSecrets{P12: cfg.CertificateSecrets.P12, Password: cfg.CertificateSecrets.Password}
			policy := signing.Policy{Now: env.now(), ExpiryWindow: 45 * 24 * time.Hour}
			plan, err := publish.Prepare(cmd.Context(), portal, vaults, stores, cfg.Manifest, names, policy)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !execute {
				return renderPushPlan(out, plan)
			}
			written, err := publish.Execute(cmd.Context(), stores, plan)
			if renderErr := renderPushed(out, written, len(plan.Secrets)*len(plan.Stores)); renderErr != nil && err == nil {
				err = renderErr
			}
			return err
		},
	}
	command.Flags().BoolVar(&execute, "execute", false, "write the secrets")
	return command
}

func renderPushPlan(out io.Writer, plan publish.Plan) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Plan: push the identity of %s (expires %s, SHA-1 %s) from %s\n", plan.Certificate.ID, date(plan.Certificate.ExpiresAt), plan.Fingerprint, plan.IdentityFrom)
	for _, store := range plan.Stores {
		fmt.Fprintf(&builder, "\nTo %s\n", store)
		table := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "  SECRET\tVALUE\tLAST UPDATED")
		for _, secret := range plan.Secrets {
			updated := "new"
			if at, ok := plan.Updated[store][secret.Name]; ok {
				updated = date(at)
			}
			fmt.Fprintf(table, "  %s\t%s\t%s\n", secret.Name, secret.Description, updated)
		}
		table.Flush()
	}
	builder.WriteString("\nRun again with --execute to write them.\n")
	return writeTrimmed(out, builder.String())
}

func renderPushed(out io.Writer, written []publish.Written, planned int) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Wrote %d of %s\n", len(written), count(planned, "secret"))
	for _, secret := range written {
		fmt.Fprintf(&builder, "  %s: %s\n", secret.Store, secret.Secret)
	}
	if len(written) < planned {
		builder.WriteString("\nCI cannot sign until every secret is written; run crem secrets push --execute again.\n")
	} else {
		builder.WriteString("\nCI now has the certificate and profiles crem checked. Once a CI build succeeds, clean up what they replaced.\n")
	}
	return writeTrimmed(out, builder.String())
}

func openSecretStores(cfg config.Config, env environment) ([]secretstore.Store, error) {
	var stores []secretstore.Store
	for _, configured := range cfg.SecretStores {
		if configured.GitHub != nil {
			tokenEnv := configured.GitHub.TokenEnv
			token := sync.OnceValues(func() (string, error) { return gitHubToken(env, tokenEnv) })
			stores = append(stores, github.New(github.DefaultBaseURL, configured.GitHub.Repository, configured.GitHub.Environment, token, &http.Client{Timeout: 60 * time.Second}))
		}
	}
	return stores, nil
}

// gitHubToken reads the configured variable, else GH_TOKEN or GITHUB_TOKEN, else asks the gh CLI.
func gitHubToken(env environment, tokenEnv string) (string, error) {
	if tokenEnv != "" {
		if token := env.getenv(tokenEnv); token != "" {
			return token, nil
		}
		return "", fmt.Errorf("$%s is empty", tokenEnv)
	}
	for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if token := env.getenv(name); token != "" {
			return token, nil
		}
	}
	output, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return "", errors.New("no GitHub token: set GH_TOKEN, or log in with gh auth login")
	}
	return strings.TrimSpace(string(output)), nil
}
