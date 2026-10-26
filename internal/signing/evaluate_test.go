package signing

import (
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

func testManifest() Manifest {
	return Manifest{
		Team: "TEAM123456",
		Profiles: []ProfileSpec{
			{Kind: AppStore, Name: MustParseTemplate("{bundleId}")},
			{Kind: AdHoc, Name: MustParseTemplate("AdHoc {bundleId}"), Devices: CarryOverDevices},
		},
		Targets: []Target{
			{App: "Demo", Environment: "Production", BundleID: "com.example.demo", Secret: "PROFILE_PRODUCTION"},
			{App: "Demo", Environment: "Production", Extension: "share", BundleID: "com.example.demo.share"},
		},
		Cleanup: Scope{Include: []string{"com.example"}, Exclude: []string{"com.example.other"}},
	}
}

func healthySnapshot() Snapshot {
	return Snapshot{
		Certificates: []Certificate{{ID: "CERT", Type: CertificateTypeDistribution, ExpiresAt: days(300)}},
		BundleIDs:    []BundleID{{Identifier: "com.example.demo"}, {Identifier: "com.example.demo.share"}},
		Profiles: []Profile{
			profile("P1", "com.example.demo", ProfileTypeIOSAppStore, "com.example.demo", days(300), "CERT"),
			profile("P2", "AdHoc com.example.demo", ProfileTypeIOSAdHoc, "com.example.demo", days(300), "CERT"),
			profile("P3", "com.example.demo.share", ProfileTypeIOSAppStore, "com.example.demo.share", days(300), "CERT"),
			profile("P4", "AdHoc com.example.demo.share", ProfileTypeIOSAdHoc, "com.example.demo.share", days(300), "CERT"),
		},
		AdHocDevices:   []Device{{ID: "D1"}, {ID: "D2"}},
		ProfileDevices: map[string][]string{"P2": {"D1", "D2"}, "P4": {"D2", "D1"}},
	}
}

func profile(id, name string, kind ProfileType, bundleID string, expires time.Time, certificates ...string) Profile {
	return Profile{ID: id, Name: name, Type: kind, State: ProfileStateActive, BundleID: bundleID, CreatedAt: expires.AddDate(-1, 0, 0), ExpiresAt: expires, CertificateIDs: certificates}
}

func policy() Policy { return Policy{Now: now, ExpiryWindow: 45 * 24 * time.Hour} }

func codes(report Report) []FindingCode {
	var result []FindingCode
	for _, finding := range report.Findings {
		result = append(result, finding.Code)
	}
	return result
}

func TestHealthyTeamHasNoFindings(t *testing.T) {
	report := Evaluate(testManifest(), healthySnapshot(), policy())

	if len(report.Findings) != 0 {
		t.Fatalf("findings = %v", report.Findings)
	}
	if report.NeedsAction() {
		t.Fatal("NeedsAction() = true")
	}
	for _, status := range report.Profiles {
		if !status.Healthy() || status.Current == nil {
			t.Fatalf("%s: healthy=%v current=%v", status.Expected.Name, status.Healthy(), status.Current)
		}
	}
	if len(report.CleanupProfiles) != 0 || len(report.CleanupCertificates) != 0 {
		t.Fatalf("cleanup = %v / %v", report.CleanupProfiles, report.CleanupCertificates)
	}
}

func TestExpiredCertificateLeavesEveryProfileExpired(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.Certificates = nil
	for index := range snapshot.Profiles {
		snapshot.Profiles[index].ExpiresAt = days(-2)
	}

	report := Evaluate(testManifest(), snapshot, policy())

	want := []FindingCode{ProfileExpired, ProfileExpired, ProfileExpired, ProfileExpired, NoHealthyDistributionCertificate}
	if got := codes(report); !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	if report.Profiles[0].LatestExpired == nil || report.Profiles[0].LatestExpired.ID != "P1" {
		t.Fatalf("latest expired = %v", report.Profiles[0].LatestExpired)
	}
	if len(report.CleanupProfiles) != 4 {
		t.Fatalf("cleanup profiles = %d", len(report.CleanupProfiles))
	}
	wantReasons := []CleanupReason{ReasonExpired, ReasonCertificatesGone, ReasonSuperseded}
	if got := report.CleanupProfiles[0].Reasons; !slices.Equal(got, wantReasons) || !report.CleanupProfiles[0].IsDead() {
		t.Fatalf("reasons = %v", got)
	}
}

func TestExpiringCertificateFlagsItsProfiles(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.Certificates[0].ExpiresAt = days(10)

	report := Evaluate(testManifest(), snapshot, policy())

	want := []FindingCode{ProfileNeedsNewCertificate, ProfileNeedsNewCertificate, ProfileNeedsNewCertificate, ProfileNeedsNewCertificate, CertificateExpiresSoon, NoHealthyDistributionCertificate}
	if got := codes(report); !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
}

func TestCurrentProfileIsTheLiveOneThatExpiresLast(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.Profiles = append(snapshot.Profiles,
		profile("NEWER", "com.example.demo", ProfileTypeIOSAppStore, "com.example.demo", days(360), "CERT"),
		profile("DEAD", "com.example.demo", ProfileTypeIOSAppStore, "com.example.demo", days(-1), "CERT"),
	)

	report := Evaluate(testManifest(), snapshot, policy())

	if got := report.Profiles[0].Current.ID; got != "NEWER" {
		t.Fatalf("current = %s", got)
	}
	if got := codes(report); !slices.Equal(got, []FindingCode{DuplicateLiveProfiles}) {
		t.Fatalf("findings = %v", got)
	}
	var candidates []string
	for _, candidate := range report.CleanupProfiles {
		candidates = append(candidates, candidate.Profile.ID)
	}
	// P1 is live and CI may still sign with it, so only the dead profile is a candidate.
	if !slices.Equal(candidates, []string{"DEAD"}) {
		t.Fatalf("candidates = %v", candidates)
	}
}

func TestMissingBundleIDAndProfilesAreReportedOnce(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.BundleIDs = snapshot.BundleIDs[:1]
	snapshot.Profiles = snapshot.Profiles[:2]

	report := Evaluate(testManifest(), snapshot, policy())

	want := []FindingCode{BundleIDMissing, ProfileMissing, ProfileMissing}
	if got := codes(report); !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	if report.Findings[0].Subject != "com.example.demo.share" {
		t.Fatalf("subject = %s", report.Findings[0].Subject)
	}
}

func TestSameNameProfileForAnotherBundleIDIsAMismatch(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.BundleIDs = append(snapshot.BundleIDs, BundleID{Identifier: "com.example.legacy"})
	snapshot.Profiles = append(snapshot.Profiles, profile("WRONG", "com.example.demo", ProfileTypeIOSAppStore, "com.example.legacy", days(100), "CERT"))

	report := Evaluate(testManifest(), snapshot, policy())

	if got := codes(report); !slices.Equal(got, []FindingCode{ProfileBundleIDMismatch}) {
		t.Fatalf("findings = %v", got)
	}
	want := []CleanupReason{ReasonUnmanagedBundleID, ReasonNonConventionalName}
	if got := report.CleanupProfiles[0].Reasons; !slices.Equal(got, want) || report.CleanupProfiles[0].IsDead() {
		t.Fatalf("reasons = %v", got)
	}
}

func TestAdHocProfileMissingDevicesIsInfo(t *testing.T) {
	snapshot := healthySnapshot()
	// Same count as the enabled devices, but D2 was swapped for a retired device.
	snapshot.ProfileDevices["P2"] = []string{"D1", "RETIRED"}

	report := Evaluate(testManifest(), snapshot, policy())

	if got := codes(report); !slices.Equal(got, []FindingCode{AdHocDeviceSubset}) || report.NeedsAction() {
		t.Fatalf("findings = %v", got)
	}
	if got := *report.Profiles[1].EnabledDeviceCount; got != 1 {
		t.Fatalf("enabled device count = %d", got)
	}
}

func TestProfilesCremDoesNotManageAreNeverCandidates(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.Profiles = append(snapshot.Profiles,
		profile("OTHER", "Other", ProfileTypeIOSAppStore, "com.example.other.app", days(-5)),
		profile("ELSE", "Else", ProfileTypeIOSAppStore, "org.elsewhere", days(-5)),
		profile("DEV", "iOS Team Provisioning Profile: com.example.demo", "IOS_APP_DEVELOPMENT", "com.example.demo", days(-5)),
		profile("WILD", "Wildcard", ProfileTypeIOSAdHoc, "com.example.*", days(-5)),
	)

	report := Evaluate(testManifest(), snapshot, policy())

	if report.UntouchedProfileCount != 4 || len(report.CleanupProfiles) != 0 {
		t.Fatalf("untouched = %d, candidates = %v", report.UntouchedProfileCount, report.CleanupProfiles)
	}
}

func TestReplacedCertificateIsACandidateButNewestIsNot(t *testing.T) {
	snapshot := healthySnapshot()
	snapshot.Certificates = append(snapshot.Certificates,
		Certificate{ID: "OLD", Type: CertificateTypeIOSDistribution, ExpiresAt: days(20)},
		Certificate{ID: "UNUSED_NEWEST", Type: CertificateTypeDistribution, ExpiresAt: days(364)},
		Certificate{ID: "DEV", Type: "DEVELOPMENT", ExpiresAt: days(5)},
	)
	snapshot.Profiles = append(snapshot.Profiles, profile("FOREIGN", "Foreign", ProfileTypeIOSAppStore, "org.elsewhere", days(20), "OLD"))

	report := Evaluate(testManifest(), snapshot, policy())

	// OLD signs a live profile outside the scope, so revoking it would break someone else's app.
	if len(report.CleanupCertificates) != 0 {
		t.Fatalf("certificate candidates = %v", report.CleanupCertificates)
	}
	snapshot.Profiles = snapshot.Profiles[:len(snapshot.Profiles)-1]
	report = Evaluate(testManifest(), snapshot, policy())
	if len(report.CleanupCertificates) != 1 || report.CleanupCertificates[0].ID != "OLD" {
		t.Fatalf("certificate candidates = %v", report.CleanupCertificates)
	}
	if got := codes(report); !slices.Equal(got, []FindingCode{CertificateExpiresSoon}) {
		t.Fatalf("findings = %v", got)
	}
}

func TestScope(t *testing.T) {
	scope := Scope{Include: []string{"com.example"}, Exclude: []string{"com.example.other"}}
	cases := map[string]bool{
		"com.example":           true,
		"com.example.demo":      true,
		"com.examples":          false,
		"com.example.other":     false,
		"com.example.other.app": false,
		"":                      false,
	}
	for bundleID, want := range cases {
		if got := scope.Contains(bundleID); got != want {
			t.Errorf("Contains(%q) = %v, want %v", bundleID, got, want)
		}
	}
}

func TestTemplate(t *testing.T) {
	template, err := ParseTemplate("PROFILE_{extension}_BASE64_{environment}")
	if err != nil {
		t.Fatal(err)
	}
	if got := template.Render(map[string]string{"extension": "SHARE", "environment": "Staging"}); got != "PROFILE_SHARE_BASE64_Staging" {
		t.Fatalf("Render = %q", got)
	}
	if !template.Uses("environment") || template.Uses("app") {
		t.Fatal("Uses reported wrong fields")
	}
	for _, invalid := range []string{"", "{nope}", "open {app"} {
		if _, err := ParseTemplate(invalid); err == nil {
			t.Errorf("ParseTemplate(%q) succeeded", invalid)
		}
	}
}
