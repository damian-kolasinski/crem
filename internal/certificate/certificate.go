// Package certificate creates distribution certificates and keeps their identities in vaults.
package certificate

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/damian-kolasinski/crem/internal/identity"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/vault"
)

// Portal reads and creates the team's certificates.
type Portal interface {
	Certificates(ctx context.Context) ([]signing.Certificate, error)
	CreateCertificate(ctx context.Context, csrPEM []byte) (signing.Certificate, []byte, error)
}

// Existing is a distribution certificate the team already has.
type Existing struct {
	Certificate signing.Certificate
	// HeldBy names the vaults holding its identity.
	HeldBy []string
}

// Plan is what creating a certificate will do.
type Plan struct {
	Team     string
	Existing []Existing
	Vaults   []string
}

// Prepare reads the team's distribution certificates and checks every vault can be read,
// so a certificate is never created that no vault could keep.
func Prepare(ctx context.Context, portal Portal, vaults []vault.Vault, team string) (Plan, error) {
	if len(vaults) == 0 {
		return Plan{}, errors.New("crem.yaml lists no vaults; add one so the new identity is kept")
	}
	plan := Plan{Team: team}
	held := map[string][]string{}
	for _, store := range vaults {
		ids, err := store.List(ctx, team)
		if err != nil && !errors.Is(err, vault.ErrNotSetUp) {
			return Plan{}, fmt.Errorf("%s: %w", store.Describe(), err)
		}
		for _, id := range ids {
			held[id] = append(held[id], store.Describe())
		}
		plan.Vaults = append(plan.Vaults, store.Describe())
	}
	certificates, err := portal.Certificates(ctx)
	if err != nil {
		return Plan{}, err
	}
	for _, certificate := range certificates {
		if certificate.Type.IsDistribution() {
			plan.Existing = append(plan.Existing, Existing{Certificate: certificate, HeldBy: held[certificate.ID]})
		}
	}
	slices.SortFunc(plan.Existing, func(left, right Existing) int {
		return left.Certificate.ExpiresAt.Compare(right.Certificate.ExpiresAt)
	})
	return plan, nil
}

// Failure is a vault that could not save the new identity.
type Failure struct {
	Vault string
	Err   error
}

// Recovery keeps the private key while the certificate is being created, and the
// identity when no vault could save it.
type Recovery interface {
	Describe() string
	KeepKey(team string, keyPEM []byte) (string, error)
	Discard(path string) error
	Save(ctx context.Context, entry vault.Entry) error
	Location(certificateID string) string
}

// Created is a new certificate and where its identity went.
type Created struct {
	Certificate signing.Certificate
	Fingerprint string
	SavedTo     []string
	Failures    []Failure
	// Recovery is where the identity was saved when no configured vault could save it.
	Recovery string
}

// Create creates a distribution certificate for a new private key and saves the identity
// to every vault. The key is written to recovery before Apple is asked for the certificate
// and removed only once a vault or recovery holds the identity, so it survives a failed
// response, a crash, or an interrupt.
func Create(ctx context.Context, portal Portal, vaults []vault.Vault, recovery Recovery, team string) (Created, error) {
	key, err := identity.NewKey()
	if err != nil {
		return Created{}, err
	}
	request, err := identity.Request(key, "crem "+team)
	if err != nil {
		return Created{}, err
	}
	password, err := identity.NewPassword()
	if err != nil {
		return Created{}, err
	}
	keyPEM, err := identity.EncodeKey(key)
	if err != nil {
		return Created{}, err
	}
	keyPath, err := recovery.KeepKey(team, keyPEM)
	if err != nil {
		return Created{}, fmt.Errorf("keeping the private key in %s before creating the certificate: %w", recovery.Describe(), err)
	}

	certificate, der, err := portal.CreateCertificate(ctx, request)
	if err != nil {
		if certificate.ID != "" {
			return Created{Certificate: certificate}, fmt.Errorf("certificate %s was created but its response was unusable (%w); its private key is kept at %s", certificate.ID, err, keyPath)
		}
		return Created{}, fmt.Errorf("%w\nApple may still have created the certificate: check App Store Connect before retrying, and revoke a new distribution certificate you did not expect. Its private key is kept at %s", err, keyPath)
	}

	created := Created{Certificate: certificate}
	issued, err := identity.New(der, key)
	if err != nil {
		return created, fmt.Errorf("certificate %s was created but cannot be used (%w); revoke it in App Store Connect", certificate.ID, err)
	}
	created.Fingerprint = issued.Fingerprint()
	p12, err := issued.P12(password)
	if err != nil {
		return created, fmt.Errorf("certificate %s was created but its .p12 could not be made (%w); its private key is kept at %s", certificate.ID, err, keyPath)
	}
	entry := vault.Entry{
		Team:          team,
		CertificateID: certificate.ID,
		SerialNumber:  certificate.SerialNumber,
		ExpiresAt:     certificate.ExpiresAt,
		P12:           p12,
		Password:      password,
	}
	for _, store := range vaults {
		if err := store.Save(ctx, entry); err != nil {
			created.Failures = append(created.Failures, Failure{Vault: store.Describe(), Err: err})
			continue
		}
		created.SavedTo = append(created.SavedTo, store.Describe())
	}
	if len(created.SavedTo) == 0 {
		if err := recovery.Save(ctx, entry); err != nil {
			return created, fmt.Errorf("certificate %s was created but no vault could save its identity, nor %s (%w); its private key is kept at %s", certificate.ID, recovery.Describe(), err, keyPath)
		}
		created.Recovery = recovery.Location(certificate.ID)
	}
	// The identity is stored, so the loose key is no longer the only copy.
	_ = recovery.Discard(keyPath)
	return created, nil
}
