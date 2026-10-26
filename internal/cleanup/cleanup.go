// Package cleanup removes what a rotation replaced: dead provisioning profiles and,
// on request, distribution certificates nothing signs with any more.
package cleanup

import (
	"context"
	"errors"
	"fmt"

	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
)

// Portal reads the team's signing state and removes profiles and certificates.
type Portal interface {
	status.Portal
	DeleteProfile(ctx context.Context, id string) error
	RevokeCertificate(ctx context.Context, id string) error
}

// Plan is what cleaning up will remove and keep.
type Plan struct {
	// Delete are dead in-scope profiles no expected profile resolves to.
	Delete []signing.ProfileCandidate
	// Keep are live leftovers: something may still use them, so crem never deletes them.
	Keep []signing.ProfileCandidate
	// Revoke are certificates no live profile uses, other than the newest; empty unless asked for.
	Revoke []signing.Certificate
	// Revocable are the certificates Revoke would hold if asked for.
	Revocable   []signing.Certificate
	VaultErrors []error
}

// Prepare decides what to remove from the evaluation's cleanup candidates.
func Prepare(ctx context.Context, portal Portal, vaults []status.Vault, manifest signing.Manifest, policy signing.Policy, revokeCertificates bool) (Plan, error) {
	checked, err := status.Check(ctx, portal, vaults, manifest, policy)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{VaultErrors: checked.VaultErrors, Revocable: checked.Report.CleanupCertificates}
	if revokeCertificates && (len(vaults) == 0 || !checked.Report.VaultsChecked) {
		return Plan{}, fmt.Errorf("revoking certificates needs every vault readable, so a certificate crem signs with is never revoked: %w", errors.Join(checked.VaultErrors...))
	}
	for _, candidate := range checked.Report.CleanupProfiles {
		if candidate.IsDead() {
			plan.Delete = append(plan.Delete, candidate)
		} else {
			plan.Keep = append(plan.Keep, candidate)
		}
	}
	if revokeCertificates {
		plan.Revoke = plan.Revocable
	}
	return plan, nil
}

// Removed is what Execute deleted and revoked.
type Removed struct {
	Profiles     []signing.Profile
	Certificates []signing.Certificate
}

// Execute deletes the dead profiles, then revokes the certificates, stopping at the first failure.
// Profiles go first: a certificate is revoked only once nothing in the plan still refers to it.
func Execute(ctx context.Context, portal Portal, plan Plan) (Removed, error) {
	var removed Removed
	for _, candidate := range plan.Delete {
		if err := portal.DeleteProfile(ctx, candidate.Profile.ID); err != nil {
			return removed, fmt.Errorf("deleting %s (%s): %w", candidate.Profile.ID, candidate.Profile.Name, err)
		}
		removed.Profiles = append(removed.Profiles, candidate.Profile)
	}
	for _, certificate := range plan.Revoke {
		if err := portal.RevokeCertificate(ctx, certificate.ID); err != nil {
			return removed, fmt.Errorf("revoking %s: %w", certificate.ID, err)
		}
		removed.Certificates = append(removed.Certificates, certificate)
	}
	return removed, nil
}
