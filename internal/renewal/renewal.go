// Package renewal issues the provisioning profiles a project expects, signed with the
// certificate whose identity crem's vaults hold.
package renewal

import (
	"context"
	"fmt"
	"slices"

	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
)

// Portal reads the team's signing state and creates profiles.
type Portal interface {
	status.Portal
	CreateProfile(ctx context.Context, profile signing.NewProfile) (signing.Profile, error)
	DeleteProfile(ctx context.Context, id string) error
}

// Item is a profile to create.
type Item struct {
	signing.Renewal
	// Devices are the Ad Hoc profile's devices; DeviceSource says where they came from.
	Devices      []signing.Device
	DeviceSource string
}

// Plan is what renewing will do.
type Plan struct {
	Certificate signing.Certificate
	Items       []Item
	Skipped     []signing.Skip
	UpToDate    int
	VaultErrors []error
}

// Prepare decides which profiles to create and, for Ad Hoc ones, with which devices.
// certificateID picks the signing certificate; empty picks the report's signing certificate.
func Prepare(ctx context.Context, portal Portal, vaults []status.Vault, manifest signing.Manifest, policy signing.Policy, certificateID string) (Plan, error) {
	checked, err := status.Check(ctx, portal, vaults, manifest, policy)
	if err != nil {
		return Plan{}, err
	}
	report := checked.Report
	plan := Plan{VaultErrors: checked.VaultErrors}
	plan.Certificate, err = checked.SigningCertificate(len(vaults), certificateID)
	if err != nil {
		return Plan{}, err
	}

	renewals, skipped, upToDate := signing.PlanRenewals(report, plan.Certificate.ID)
	plan.Skipped, plan.UpToDate = skipped, upToDate
	var enabled []signing.Device
	for _, renewal := range renewals {
		item := Item{Renewal: renewal}
		if renewal.Expected.Spec.Kind == signing.AdHoc {
			if enabled == nil {
				if enabled, err = portal.AdHocDevices(ctx); err != nil {
					return Plan{}, err
				}
			}
			reason, err := selectDevices(ctx, portal, &item, enabled)
			if err != nil {
				return Plan{}, err
			}
			if reason != "" {
				plan.Skipped = append(plan.Skipped, signing.Skip{Expected: renewal.Expected, Reason: reason})
				continue
			}
		}
		plan.Items = append(plan.Items, item)
	}
	return plan, nil
}

func selectDevices(ctx context.Context, portal Portal, item *Item, enabled []signing.Device) (signing.SkipReason, error) {
	switch {
	case item.Expected.Spec.Devices == signing.AllDevices:
		item.Devices = enabled
		item.DeviceSource = "all enabled devices"
	case item.Replaces == nil:
		return signing.SkipNoDeviceSource, nil
	default:
		previous, err := portal.ProfileDevices(ctx, item.Replaces.ID)
		if err != nil {
			return "", err
		}
		for _, device := range enabled {
			if slices.ContainsFunc(previous, func(candidate signing.Device) bool { return candidate.ID == device.ID }) {
				item.Devices = append(item.Devices, device)
			}
		}
		item.DeviceSource = fmt.Sprintf("enabled devices of %s", item.Replaces.ID)
	}
	if len(item.Devices) == 0 {
		return signing.SkipNoEnabledDevices, nil
	}
	return "", nil
}

// Created is a profile Execute created, with the dead profiles it deleted first.
type Created struct {
	Item    Item
	Profile signing.Profile
	Removed []signing.Profile
}

// Execute creates the plan's profiles in order, deleting each one's dead namesakes first,
// and stops at the first failure. Running Prepare again afterwards picks up where it stopped.
func Execute(ctx context.Context, portal Portal, plan Plan) ([]Created, error) {
	var created []Created
	for _, item := range plan.Items {
		var removed []signing.Profile
		for _, dead := range item.Removes {
			if err := portal.DeleteProfile(ctx, dead.ID); err != nil {
				return created, fmt.Errorf("deleting the dead profile %s (%s) before creating its replacement: %w", dead.ID, dead.Name, err)
			}
			removed = append(removed, dead)
		}
		request := signing.NewProfile{
			Name:          item.Expected.Name,
			Type:          item.Expected.Spec.Kind.ProfileType(),
			BundleID:      item.Expected.Target.BundleID,
			CertificateID: plan.Certificate.ID,
		}
		for _, device := range item.Devices {
			request.DeviceIDs = append(request.DeviceIDs, device.ID)
		}
		profile, err := portal.CreateProfile(ctx, request)
		if err != nil {
			return created, fmt.Errorf("creating %s: %w", item.Expected.Name, err)
		}
		created = append(created, Created{Item: item, Profile: profile, Removed: removed})
	}
	return created, nil
}
