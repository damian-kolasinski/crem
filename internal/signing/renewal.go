package signing

import "slices"

// SigningCertificate is the certificate new profiles are signed with: the valid
// distribution certificate that expires last among those whose identity a vault holds.
// It requires the vaults to have been read.
func (r Report) SigningCertificate() (Certificate, bool) {
	var held []Certificate
	for _, status := range r.Certificates {
		if r.VaultsChecked && status.Held && status.Certificate.Type.IsDistribution() && !status.ExpiresSoon {
			held = append(held, status.Certificate)
		}
	}
	if len(held) == 0 {
		return Certificate{}, false
	}
	return slices.MaxFunc(held, func(left, right Certificate) int { return left.ExpiresAt.Compare(right.ExpiresAt) }), true
}

// RenewalReason says why an expected profile needs a new profile.
type RenewalReason string

const (
	RenewMissing          RenewalReason = "missing"
	RenewExpired          RenewalReason = "expired"
	RenewExpiring         RenewalReason = "expiring"
	RenewOtherCertificate RenewalReason = "signed with another certificate"
)

// SkipReason says why an expected profile cannot be renewed yet.
type SkipReason string

const (
	SkipBundleIDMissing    SkipReason = "bundle ID is not registered"
	SkipNameTakenElsewhere SkipReason = "a live profile with this name belongs to another bundle ID; delete it first"
	SkipNoDeviceSource     SkipReason = "no previous profile to carry devices over from; set devices: all for this kind"
	SkipNoEnabledDevices   SkipReason = "it would include no enabled devices; register devices or set devices: all for this kind"
)

// Renewal is an expected profile that needs a new profile.
type Renewal struct {
	Expected ExpectedProfile
	Reason   RenewalReason
	// Replaces is the profile the new one supersedes: the current one, or the latest expired one.
	Replaces *Profile
	// Removes are dead profiles with the same name, deleted first: they cannot sign anything,
	// and App Store Connect may refuse a name that is already taken.
	Removes []Profile
}

// Skip is an expected profile crem cannot renew yet.
type Skip struct {
	Expected ExpectedProfile
	Reason   SkipReason
}

// PlanRenewals decides which expected profiles need a new profile signed with the certificate.
func PlanRenewals(report Report, certificateID string) (renewals []Renewal, skipped []Skip, upToDate int) {
	for _, status := range report.Profiles {
		renew := func(reason RenewalReason, replaces *Profile) {
			renewals = append(renewals, Renewal{Expected: status.Expected, Reason: reason, Replaces: replaces, Removes: status.DeadNamesakes})
		}
		switch {
		case !status.BundleIDRegistered:
			skipped = append(skipped, Skip{Expected: status.Expected, Reason: SkipBundleIDMissing})
		case slices.Contains(status.Issues, ProfileBundleIDMismatch):
			skipped = append(skipped, Skip{Expected: status.Expected, Reason: SkipNameTakenElsewhere})
		case status.Current == nil && status.LatestExpired != nil:
			renew(RenewExpired, status.LatestExpired)
		case status.Current == nil:
			renew(RenewMissing, nil)
		case slices.Contains(status.Issues, ProfileExpiresSoon):
			renew(RenewExpiring, status.Current)
		case !status.Current.UsesCertificate(certificateID):
			renew(RenewOtherCertificate, status.Current)
		default:
			upToDate++
		}
	}
	return renewals, skipped, upToDate
}

// NewProfile is a provisioning profile to create.
type NewProfile struct {
	Name          string
	Type          ProfileType
	BundleID      string
	CertificateID string
	// DeviceIDs are the devices of an Ad Hoc profile.
	DeviceIDs []string
}
