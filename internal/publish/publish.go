// Package publish hands CI what it signs with: the signing identity and the App Store
// profiles, checked against each other, written to CI's secret stores all at once.
package publish

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damian-kolasinski/crem/internal/identity"
	"github.com/damian-kolasinski/crem/internal/provisioning"
	"github.com/damian-kolasinski/crem/internal/secretstore"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
	"github.com/damian-kolasinski/crem/internal/vault"
)

// Portal reads the team's signing state and downloads profiles.
type Portal interface {
	status.Portal
	ProfileContent(ctx context.Context, id string) ([]byte, error)
}

// CertificateSecrets names the secrets that carry the .p12 and its password.
type CertificateSecrets struct {
	P12      string
	Password string
}

// Secret is one secret to write. Its value never leaves the package except to a store.
type Secret struct {
	Name        string
	Description string
	value       []byte
}

// String names the secret; its value is never formatted.
func (s Secret) String() string { return s.Name }

// GoString keeps %#v from printing the value.
func (s Secret) GoString() string { return "publish.Secret{Name: " + s.Name + "}" }

// Plan is what pushing will write.
type Plan struct {
	Certificate signing.Certificate
	Fingerprint string
	// IdentityFrom names the vault the identity was read from.
	IdentityFrom string
	Secrets      []Secret
	Stores       []string
	// Updated holds, by store and secret name, when each existing secret was last updated.
	Updated     map[string]map[string]time.Time
	VaultErrors []error
}

// Prepare gathers the identity and every App Store profile with a secret, and checks they
// belong together. It refuses unless every profile secret can be written, because CI signs
// every target with the one certificate: a partial update would leave CI unable to sign.
func Prepare(ctx context.Context, portal Portal, vaults []vault.Vault, stores []secretstore.Store, manifest signing.Manifest, names CertificateSecrets, policy signing.Policy) (Plan, error) {
	if len(stores) == 0 {
		return Plan{}, errors.New("crem.yaml lists no secretStores")
	}
	readers := make([]status.Vault, len(vaults))
	for index, store := range vaults {
		readers[index] = store
	}
	checked, err := status.Check(ctx, portal, readers, manifest, policy)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{VaultErrors: checked.VaultErrors, Updated: map[string]map[string]time.Time{}}
	if plan.Certificate, err = checked.SigningCertificate(len(vaults), ""); err != nil {
		return Plan{}, err
	}

	issued, entry, from, err := loadIdentity(ctx, vaults, manifest.Team, plan.Certificate)
	if err != nil {
		return Plan{}, err
	}
	plan.Fingerprint, plan.IdentityFrom = issued.Fingerprint(), from
	plan.Secrets = append(plan.Secrets,
		Secret{Name: names.P12, Description: fmt.Sprintf(".p12 of %s", plan.Certificate.ID), value: []byte(base64.StdEncoding.EncodeToString(entry.P12))},
		Secret{Name: names.Password, Description: "its password", value: []byte(entry.Password)},
	)

	var problems []string
	for _, profile := range checked.Report.Profiles {
		target := profile.Expected.Target
		if profile.Expected.Spec.Kind != signing.AppStore || target.Secret == "" {
			continue
		}
		switch {
		case profile.Current == nil:
			problems = append(problems, fmt.Sprintf("%s has no live profile", profile.Expected.Name))
			continue
		case !profile.Current.UsesCertificate(plan.Certificate.ID):
			problems = append(problems, fmt.Sprintf("%s (%s) is signed with another certificate", profile.Expected.Name, profile.Current.ID))
			continue
		case !profile.Healthy():
			problems = append(problems, fmt.Sprintf("%s (%s) needs renewing", profile.Expected.Name, profile.Current.ID))
			continue
		}
		content, err := portal.ProfileContent(ctx, profile.Current.ID)
		if err != nil {
			return Plan{}, err
		}
		if err := verify(content, profile.Expected, manifest.Team, issued.Fingerprint(), policy.Now); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%s): %v", profile.Expected.Name, profile.Current.ID, err))
			continue
		}
		plan.Secrets = append(plan.Secrets, Secret{
			Name:        target.Secret,
			Description: fmt.Sprintf("%s (%s, expires %s)", profile.Expected.Name, profile.Current.ID, profile.Current.ExpiresAt.UTC().Format(time.DateOnly)),
			value:       []byte(base64.StdEncoding.EncodeToString(content)),
		})
	}
	if len(problems) > 0 {
		return Plan{}, fmt.Errorf("every App Store profile with a secret must be live and contain %s before CI gets it; renew the profiles first:\n  %s", plan.Certificate.ID, strings.Join(problems, "\n  "))
	}

	for _, store := range stores {
		updated, err := store.Updated(ctx)
		if err != nil {
			return Plan{}, err
		}
		plan.Stores = append(plan.Stores, store.Describe())
		plan.Updated[store.Describe()] = updated
	}
	return plan, nil
}

// loadIdentity reads the certificate's identity from the first vault that holds it and checks it is that certificate.
func loadIdentity(ctx context.Context, vaults []vault.Vault, team string, certificate signing.Certificate) (identity.Identity, vault.Entry, string, error) {
	for _, store := range vaults {
		entry, err := store.Load(ctx, team, certificate.ID)
		if errors.Is(err, vault.ErrNotFound) || errors.Is(err, vault.ErrNotSetUp) {
			continue
		}
		if err != nil {
			return identity.Identity{}, vault.Entry{}, "", fmt.Errorf("%s: %w", store.Describe(), err)
		}
		issued, err := identity.Open(entry.P12, entry.Password)
		if err != nil {
			return identity.Identity{}, vault.Entry{}, "", fmt.Errorf("%s holds an unusable identity for %s: %w", store.Describe(), certificate.ID, err)
		}
		if !strings.EqualFold(strings.TrimLeft(issued.Certificate.SerialNumber.Text(16), "0"), strings.TrimLeft(certificate.SerialNumber, "0")) {
			return identity.Identity{}, vault.Entry{}, "", fmt.Errorf("%s holds an identity for %s whose serial number is not that certificate's", store.Describe(), certificate.ID)
		}
		return issued, entry, store.Describe(), nil
	}
	return identity.Identity{}, vault.Entry{}, "", fmt.Errorf("no vault could load the identity of %s", certificate.ID)
}

// verify checks a downloaded profile is the expected App Store profile and contains the identity's certificate.
func verify(content []byte, expected signing.ExpectedProfile, team, fingerprint string, now time.Time) error {
	profile, err := provisioning.Parse(content)
	if err != nil {
		return err
	}
	return profile.Check(provisioning.Expectation{Name: expected.Name, TeamID: team, BundleID: expected.Target.BundleID, CertificateSHA: fingerprint}, now)
}

// Written is a secret Execute wrote.
type Written struct {
	Store  string
	Secret string
}

// Execute writes every secret to every store, stopping at the first failure. Running
// it again rewrites everything, which completes an interrupted push.
func Execute(ctx context.Context, stores []secretstore.Store, plan Plan) ([]Written, error) {
	var written []Written
	for _, store := range stores {
		for _, secret := range plan.Secrets {
			if err := store.Set(ctx, secret.Name, secret.value); err != nil {
				return written, fmt.Errorf("writing %s: %w", secret.Name, err)
			}
			written = append(written, Written{Store: store.Describe(), Secret: secret.Name})
		}
	}
	return written, nil
}
