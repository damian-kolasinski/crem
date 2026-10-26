package signing

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Snapshot is the team's signing state as App Store Connect reports it.
type Snapshot struct {
	Certificates []Certificate
	BundleIDs    []BundleID
	Profiles     []Profile
	// AdHocDevices are the enabled devices Ad Hoc profiles accept.
	AdHocDevices []Device
	// ProfileDevices holds the device IDs of the profiles they were fetched for, by profile ID.
	ProfileDevices map[string][]string
	// VaultsChecked is true when crem's vaults were read; HeldCertificateIDs then lists
	// the certificates whose identities they hold.
	VaultsChecked      bool
	HeldCertificateIDs map[string]bool
}

// usable reports whether crem can sign with the certificate past the expiry window:
// a valid distribution certificate whose identity, when vaults were checked, a vault holds.
func (s Snapshot) usable(certificate Certificate, policy Policy) bool {
	return certificate.Type.IsDistribution() && !policy.expiresSoon(certificate.ExpiresAt) &&
		(!s.VaultsChecked || s.HeldCertificateIDs[certificate.ID])
}

// Policy sets how far ahead an evaluation looks.
type Policy struct {
	Now time.Time
	// ExpiryWindow is how long before expiry a certificate or profile needs renewing.
	ExpiryWindow time.Duration
}

func (p Policy) expiresSoon(at time.Time) bool {
	return at.Before(p.Now.Add(p.ExpiryWindow))
}

// Severity says whether a finding needs action.
type Severity string

const (
	SeverityAction Severity = "action"
	SeverityInfo   Severity = "info"
)

// FindingCode identifies a kind of finding.
type FindingCode string

const (
	NoHealthyDistributionCertificate FindingCode = "NO_HEALTHY_DISTRIBUTION_CERTIFICATE"
	CertificateExpiresSoon           FindingCode = "CERTIFICATE_EXPIRES_SOON"
	BundleIDMissing                  FindingCode = "BUNDLE_ID_MISSING"
	ProfileMissing                   FindingCode = "PROFILE_MISSING"
	ProfileExpired                   FindingCode = "PROFILE_EXPIRED"
	ProfileExpiresSoon               FindingCode = "PROFILE_EXPIRES_SOON"
	ProfileNeedsNewCertificate       FindingCode = "PROFILE_NEEDS_NEW_CERTIFICATE"
	ProfileBundleIDMismatch          FindingCode = "PROFILE_BUNDLE_ID_MISMATCH"
	DuplicateLiveProfiles            FindingCode = "DUPLICATE_LIVE_PROFILES"
	AdHocDeviceSubset                FindingCode = "ADHOC_PROFILE_DEVICE_SUBSET"
)

// Severity of findings with this code.
func (c FindingCode) Severity() Severity {
	if c == DuplicateLiveProfiles || c == AdHocDeviceSubset {
		return SeverityInfo
	}
	return SeverityAction
}

// Finding is one thing about the team's signing that differs from what the project expects.
type Finding struct {
	Code    FindingCode
	Subject string
	Detail  string
}

// CertificateStatus is a certificate with what depends on it.
type CertificateStatus struct {
	Certificate      Certificate
	LiveProfileCount int
	ExpiresSoon      bool
	// Held is true when a vault holds the certificate's identity; always false when vaults were not checked.
	Held bool
}

// ProfileStatus is an expected profile with the live profile that currently fulfils it.
type ProfileStatus struct {
	Expected ExpectedProfile
	// BundleIDRegistered is false when the target's bundle ID is not registered.
	BundleIDRegistered bool
	// Current is the live profile with the expected name, type, and bundle ID that expires last; nil when none is live.
	Current *Profile
	// LatestExpired is the newest dead profile with the expected name, type, and bundle ID, when no profile is live.
	LatestExpired *Profile
	// DeadNamesakes are dead in-scope profiles with the expected name, which a new profile replaces.
	DeadNamesakes []Profile
	// EnabledDeviceCount is how many of the enabled Ad Hoc devices the Current profile includes, when known.
	EnabledDeviceCount *int
	Issues             []FindingCode
}

// Healthy reports whether the profile needs no action.
func (s ProfileStatus) Healthy() bool {
	return !slices.ContainsFunc(s.Issues, func(code FindingCode) bool { return code.Severity() == SeverityAction })
}

// CleanupReason says why a profile is a cleanup candidate.
type CleanupReason string

const (
	ReasonNotActive           CleanupReason = "NOT_ACTIVE"
	ReasonExpired             CleanupReason = "EXPIRED"
	ReasonCertificatesGone    CleanupReason = "CERTIFICATES_REVOKED_OR_EXPIRED"
	ReasonUnmanagedBundleID   CleanupReason = "UNMANAGED_BUNDLE_ID"
	ReasonSuperseded          CleanupReason = "SUPERSEDED"
	ReasonNonConventionalName CleanupReason = "NON_CONVENTIONAL_NAME"
)

// ProfileCandidate is an in-scope profile no expected profile resolves to.
type ProfileCandidate struct {
	Profile Profile
	Reasons []CleanupReason
}

// IsDead reports whether the profile can no longer sign anything.
func (c ProfileCandidate) IsDead() bool {
	return slices.ContainsFunc(c.Reasons, func(reason CleanupReason) bool {
		return reason == ReasonNotActive || reason == ReasonExpired || reason == ReasonCertificatesGone
	})
}

// Report is the outcome of comparing a manifest with a snapshot.
type Report struct {
	Team             string
	Policy           Policy
	AdHocDeviceCount int
	Certificates     []CertificateStatus
	Profiles         []ProfileStatus
	Findings         []Finding
	// CleanupProfiles are in-scope profiles of the configured kinds that no expected profile resolves to.
	CleanupProfiles []ProfileCandidate
	// CleanupCertificates are distribution certificates no live profile uses, except the newest.
	CleanupCertificates []Certificate
	// VaultsChecked is true when the vaults were read, so CertificateStatus.Held is meaningful.
	VaultsChecked bool
	// UntouchedProfileCount counts profiles crem never touches: outside the cleanup scope, of
	// kinds the manifest does not configure, or for wildcard App IDs.
	UntouchedProfileCount int
}

// NeedsAction reports whether any finding needs action.
func (r Report) NeedsAction() bool {
	return slices.ContainsFunc(r.Findings, func(finding Finding) bool { return finding.Code.Severity() == SeverityAction })
}

type profileIdentity struct {
	name     string
	kind     ProfileType
	bundleID string
}

// CurrentProfile returns the live profile that fulfils an expected profile:
// the one with its name, type, and bundle ID that expires last, newest first on ties.
func CurrentProfile(profiles []Profile, expected ExpectedProfile, now time.Time) (Profile, bool) {
	live := matchingProfiles(profiles, expected, func(profile Profile) bool { return profile.IsLive(now) })
	if len(live) == 0 {
		return Profile{}, false
	}
	return live[0], true
}

func matchingProfiles(profiles []Profile, expected ExpectedProfile, keep func(Profile) bool) []Profile {
	var matching []Profile
	for _, profile := range profiles {
		if profile.Name == expected.Name && profile.Type == expected.Spec.Kind.ProfileType() && profile.BundleID == expected.Target.BundleID && keep(profile) {
			matching = append(matching, profile)
		}
	}
	slices.SortStableFunc(matching, func(left, right Profile) int {
		return cmp.Or(right.ExpiresAt.Compare(left.ExpiresAt), right.CreatedAt.Compare(left.CreatedAt))
	})
	return matching
}

// Evaluate compares what the manifest expects with what the snapshot reports.
func Evaluate(manifest Manifest, snapshot Snapshot, policy Policy) Report {
	report := Report{Team: manifest.Team, Policy: policy, AdHocDeviceCount: len(snapshot.AdHocDevices), VaultsChecked: snapshot.VaultsChecked}
	certificatesByID := make(map[string]Certificate, len(snapshot.Certificates))
	for _, certificate := range snapshot.Certificates {
		certificatesByID[certificate.ID] = certificate
	}
	registered := make(map[string]bool, len(snapshot.BundleIDs))
	for _, bundleID := range snapshot.BundleIDs {
		registered[bundleID.Identifier] = true
	}
	addFinding := func(code FindingCode, subject, detail string) {
		report.Findings = append(report.Findings, Finding{Code: code, Subject: subject, Detail: detail})
	}

	reportedMissingBundleIDs := map[string]bool{}
	// Every live profile an expected profile could resolve to is protected: CI may still sign
	// with an older one than the current, and crem cannot see which one its secrets hold.
	protected := map[string]bool{}
	conventional := map[profileIdentity]bool{}
	managedTypes := map[ProfileType]bool{}
	for _, expected := range manifest.ExpectedProfiles() {
		managedTypes[expected.Spec.Kind.ProfileType()] = true
		conventional[profileIdentity{expected.Name, expected.Spec.Kind.ProfileType(), expected.Target.BundleID}] = true
		status := ProfileStatus{Expected: expected, BundleIDRegistered: registered[expected.Target.BundleID]}
		issue := func(code FindingCode, detail string) {
			status.Issues = append(status.Issues, code)
			addFinding(code, expected.Name, detail)
		}
		if !status.BundleIDRegistered {
			status.Issues = append(status.Issues, BundleIDMissing)
			if !reportedMissingBundleIDs[expected.Target.BundleID] {
				reportedMissingBundleIDs[expected.Target.BundleID] = true
				addFinding(BundleIDMissing, expected.Target.BundleID, "")
			}
		}
		for _, profile := range snapshot.Profiles {
			if profile.Name == expected.Name && profile.Type == expected.Spec.Kind.ProfileType() && profile.BundleID != expected.Target.BundleID && profile.IsLive(policy.Now) {
				issue(ProfileBundleIDMismatch, fmt.Sprintf("%s targets %s", profile.ID, profile.BundleID))
			}
		}

		for _, profile := range snapshot.Profiles {
			if profile.Name == expected.Name && !profile.IsLive(policy.Now) && manifest.Cleanup.Contains(profile.BundleID) {
				status.DeadNamesakes = append(status.DeadNamesakes, profile)
			}
		}
		live := matchingProfiles(snapshot.Profiles, expected, func(profile Profile) bool { return profile.IsLive(policy.Now) })
		if len(live) == 0 {
			dead := matchingProfiles(snapshot.Profiles, expected, func(Profile) bool { return true })
			if len(dead) > 0 {
				status.LatestExpired = &dead[0]
				issue(ProfileExpired, "expired "+dead[0].ExpiresAt.UTC().Format(time.DateOnly))
			} else {
				issue(ProfileMissing, "")
			}
			report.Profiles = append(report.Profiles, status)
			continue
		}

		for _, profile := range live {
			protected[profile.ID] = true
		}
		current := live[0]
		status.Current = &current
		if policy.expiresSoon(current.ExpiresAt) {
			issue(ProfileExpiresSoon, "expires "+current.ExpiresAt.UTC().Format(time.DateOnly))
		}
		if !slices.ContainsFunc(current.CertificateIDs, func(id string) bool {
			certificate, known := certificatesByID[id]
			return known && snapshot.usable(certificate, policy)
		}) {
			issue(ProfileNeedsNewCertificate, "")
		}
		if len(live) > 1 {
			issue(DuplicateLiveProfiles, fmt.Sprintf("%d live profiles", len(live)))
		}
		if deviceIDs, known := snapshot.ProfileDevices[current.ID]; known && expected.Spec.Kind == AdHoc {
			included := 0
			for _, device := range snapshot.AdHocDevices {
				if slices.Contains(deviceIDs, device.ID) {
					included++
				}
			}
			status.EnabledDeviceCount = &included
			if included < len(snapshot.AdHocDevices) {
				issue(AdHocDeviceSubset, fmt.Sprintf("includes %d of %d enabled devices", included, len(snapshot.AdHocDevices)))
			}
		}
		report.Profiles = append(report.Profiles, status)
	}

	var distribution []Certificate
	for _, certificate := range snapshot.Certificates {
		liveCount := 0
		for _, profile := range snapshot.Profiles {
			if profile.IsLive(policy.Now) && profile.UsesCertificate(certificate.ID) {
				liveCount++
			}
		}
		status := CertificateStatus{Certificate: certificate, LiveProfileCount: liveCount, ExpiresSoon: policy.expiresSoon(certificate.ExpiresAt), Held: snapshot.HeldCertificateIDs[certificate.ID]}
		report.Certificates = append(report.Certificates, status)
		if certificate.Type.IsDistribution() {
			distribution = append(distribution, certificate)
			if status.ExpiresSoon {
				addFinding(CertificateExpiresSoon, certificate.ID, fmt.Sprintf("expires %s, %d live profiles", certificate.ExpiresAt.UTC().Format(time.DateOnly), liveCount))
			}
		}
	}
	if !slices.ContainsFunc(distribution, func(certificate Certificate) bool { return snapshot.usable(certificate, policy) }) {
		detail := fmt.Sprintf("none valid beyond %d days", int(policy.ExpiryWindow.Hours()/24))
		if snapshot.VaultsChecked {
			detail += " with its identity in a vault"
		}
		addFinding(NoHealthyDistributionCertificate, manifest.Team, detail)
	}

	for _, profile := range snapshot.Profiles {
		if !manifest.Cleanup.Contains(profile.BundleID) || !managedTypes[profile.Type] || strings.Contains(profile.BundleID, "*") {
			report.UntouchedProfileCount++
			continue
		}
		if protected[profile.ID] {
			continue
		}
		var reasons []CleanupReason
		if profile.State != ProfileStateActive {
			reasons = append(reasons, ReasonNotActive)
		}
		if !profile.ExpiresAt.After(policy.Now) {
			reasons = append(reasons, ReasonExpired)
		}
		if !slices.ContainsFunc(profile.CertificateIDs, func(id string) bool { _, known := certificatesByID[id]; return known }) {
			reasons = append(reasons, ReasonCertificatesGone)
		}
		if _, managed := manifest.Target(profile.BundleID); !managed {
			reasons = append(reasons, ReasonUnmanagedBundleID)
		}
		if conventional[profileIdentity{profile.Name, profile.Type, profile.BundleID}] {
			reasons = append(reasons, ReasonSuperseded)
		} else {
			reasons = append(reasons, ReasonNonConventionalName)
		}
		report.CleanupProfiles = append(report.CleanupProfiles, ProfileCandidate{Profile: profile, Reasons: reasons})
	}

	// A certificate any live profile uses is never a candidate, whoever owns the profile: revoking it
	// would stop that profile from signing. Nor is the newest, which a rotation may have just created.
	if len(distribution) > 0 {
		newest := slices.MaxFunc(distribution, func(left, right Certificate) int { return left.ExpiresAt.Compare(right.ExpiresAt) })
		for _, certificate := range distribution {
			inUse := slices.ContainsFunc(snapshot.Profiles, func(profile Profile) bool {
				return profile.IsLive(policy.Now) && profile.UsesCertificate(certificate.ID)
			})
			if certificate.ID != newest.ID && !inUse {
				report.CleanupCertificates = append(report.CleanupCertificates, certificate)
			}
		}
	}
	return report
}
