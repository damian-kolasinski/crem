// Package renewal issues the provisioning profiles a project expects, signed with the
// certificate whose identity crem's vaults hold.
package renewal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
	"github.com/damian-kolasinski/crem/internal/vault"
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
	// Profiles must be signed with a certificate CI can get the identity of, so the vaults decide.
	if len(vaults) == 0 {
		return Plan{}, errors.New("crem.yaml lists no vaults, so crem cannot tell which certificate CI can sign with")
	}
	if !report.VaultsChecked {
		// A vault not set up on this machine holds nothing; any other failure leaves holdings unknown.
		for _, vaultError := range checked.VaultErrors {
			if !errors.Is(vaultError, vault.ErrNotSetUp) {
				return Plan{}, fmt.Errorf("every vault must be readable to choose the signing certificate: %w", errors.Join(checked.VaultErrors...))
			}
		}
		report.VaultsChecked = true
	}
	if certificateID == "" {
		certificate, ok := report.SigningCertificate()
		if !ok {
			return Plan{}, errors.New(noSigningCertificate(report))
		}
		plan.Certificate = certificate
	} else {
		index := slices.IndexFunc(report.Certificates, func(status signing.CertificateStatus) bool { return status.Certificate.ID == certificateID })
		if index < 0 || !report.Certificates[index].Certificate.Type.IsDistribution() || !report.Certificates[index].Certificate.ExpiresAt.After(policy.Now) {
			return Plan{}, fmt.Errorf("certificate %s is not a valid distribution certificate of the team", certificateID)
		}
		if !report.Certificates[index].Held {
			return Plan{}, fmt.Errorf("no vault holds the identity of certificate %s, so CI could not sign with its profiles", certificateID)
		}
		plan.Certificate = report.Certificates[index].Certificate
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

// noSigningCertificate explains why no certificate can sign, without nudging the
// operator to create a certificate when one exists that merely is not in a vault.
func noSigningCertificate(report signing.Report) string {
	var unheld []string
	for _, status := range report.Certificates {
		if status.Certificate.Type.IsDistribution() && !status.ExpiresSoon && !status.Held {
			unheld = append(unheld, status.Certificate.ID)
		}
	}
	message := fmt.Sprintf("no vault holds the identity of a distribution certificate valid beyond %d days", int(report.Policy.ExpiryWindow.Hours()/24))
	if len(unheld) > 0 {
		return message + fmt.Sprintf("; %s is valid but its identity is not in a vault, so it was created elsewhere: create a new certificate with crem, or ask its owner", strings.Join(unheld, ", "))
	}
	return message + "; create one with crem cert create"
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
