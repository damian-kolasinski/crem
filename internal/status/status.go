// Package status reports how a team's signing compares with what a project expects.
package status

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/damian-kolasinski/crem/internal/signing"
)

// Portal reads a team's signing state from App Store Connect.
type Portal interface {
	Certificates(ctx context.Context) ([]signing.Certificate, error)
	BundleIDs(ctx context.Context) ([]signing.BundleID, error)
	Profiles(ctx context.Context) ([]signing.Profile, error)
	AdHocDevices(ctx context.Context) ([]signing.Device, error)
	ProfileDevices(ctx context.Context, profileID string) ([]signing.Device, error)
}

// Vault lists the identities a vault holds.
type Vault interface {
	Describe() string
	List(ctx context.Context, team string) ([]string, error)
}

// Result is a report with the vaults that could not be read.
type Result struct {
	Report signing.Report
	// VaultErrors are vaults that could not be read. Unless every vault was read, the
	// report does not require certificates to be held in a vault, to avoid false alarms.
	VaultErrors []error
}

// Check reads the team's signing state and its vaults, and evaluates them against the manifest.
func Check(ctx context.Context, portal Portal, vaults []Vault, manifest signing.Manifest, policy signing.Policy) (Result, error) {
	var snapshot signing.Snapshot
	var result Result
	snapshot.HeldCertificateIDs = map[string]bool{}
	for _, vault := range vaults {
		ids, err := vault.List(ctx, manifest.Team)
		if err != nil {
			result.VaultErrors = append(result.VaultErrors, fmt.Errorf("%s: %w", vault.Describe(), err))
			continue
		}
		for _, id := range ids {
			snapshot.HeldCertificateIDs[id] = true
		}
	}
	snapshot.VaultsChecked = len(vaults) > 0 && len(result.VaultErrors) == 0

	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() (err error) { snapshot.Certificates, err = portal.Certificates(groupContext); return })
	group.Go(func() (err error) { snapshot.BundleIDs, err = portal.BundleIDs(groupContext); return })
	group.Go(func() (err error) { snapshot.Profiles, err = portal.Profiles(groupContext); return })
	group.Go(func() (err error) { snapshot.AdHocDevices, err = portal.AdHocDevices(groupContext); return })
	if err := group.Wait(); err != nil {
		return Result{}, err
	}

	var adHocProfileIDs []string
	for _, expected := range manifest.ExpectedProfiles() {
		if expected.Spec.Kind != signing.AdHoc {
			continue
		}
		if current, ok := signing.CurrentProfile(snapshot.Profiles, expected, policy.Now); ok {
			adHocProfileIDs = append(adHocProfileIDs, current.ID)
		}
	}
	devices := make([][]string, len(adHocProfileIDs))
	group, groupContext = errgroup.WithContext(ctx)
	group.SetLimit(4)
	for index, id := range adHocProfileIDs {
		group.Go(func() error {
			included, err := portal.ProfileDevices(groupContext, id)
			for _, device := range included {
				devices[index] = append(devices[index], device.ID)
			}
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return Result{}, err
	}
	snapshot.ProfileDevices = make(map[string][]string, len(adHocProfileIDs))
	for index, id := range adHocProfileIDs {
		snapshot.ProfileDevices[id] = devices[index]
	}

	result.Report = signing.Evaluate(manifest, snapshot, policy)
	return result, nil
}
