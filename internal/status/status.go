// Package status reports how a team's signing compares with what a project expects.
package status

import (
	"context"

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

// Check reads the team's signing state and evaluates it against the manifest.
func Check(ctx context.Context, portal Portal, manifest signing.Manifest, policy signing.Policy) (signing.Report, error) {
	var snapshot signing.Snapshot
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() (err error) { snapshot.Certificates, err = portal.Certificates(groupContext); return })
	group.Go(func() (err error) { snapshot.BundleIDs, err = portal.BundleIDs(groupContext); return })
	group.Go(func() (err error) { snapshot.Profiles, err = portal.Profiles(groupContext); return })
	group.Go(func() (err error) { snapshot.AdHocDevices, err = portal.AdHocDevices(groupContext); return })
	if err := group.Wait(); err != nil {
		return signing.Report{}, err
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
		return signing.Report{}, err
	}
	snapshot.ProfileDevices = make(map[string][]string, len(adHocProfileIDs))
	for index, id := range adHocProfileIDs {
		snapshot.ProfileDevices[id] = devices[index]
	}

	return signing.Evaluate(manifest, snapshot, policy), nil
}
