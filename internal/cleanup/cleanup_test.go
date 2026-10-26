package cleanup

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

type team struct {
	certificates []signing.Certificate
	profiles     []signing.Profile
	revoked      []string
}

func (t *team) Certificates(context.Context) ([]signing.Certificate, error) {
	return t.certificates, nil
}
func (t *team) BundleIDs(context.Context) ([]signing.BundleID, error) {
	return []signing.BundleID{{Identifier: "com.example.demo"}}, nil
}
func (t *team) Profiles(context.Context) ([]signing.Profile, error)    { return t.profiles, nil }
func (t *team) AdHocDevices(context.Context) ([]signing.Device, error) { return nil, nil }
func (t *team) ProfileDevices(context.Context, string) ([]signing.Device, error) {
	return nil, nil
}
func (t *team) DeleteProfile(_ context.Context, id string) error {
	t.profiles = slices.DeleteFunc(t.profiles, func(profile signing.Profile) bool { return profile.ID == id })
	return nil
}
func (t *team) RevokeCertificate(_ context.Context, id string) error {
	t.revoked = append(t.revoked, id)
	return nil
}

func profile(id, name, bundleID string, expires time.Time, certificate string) signing.Profile {
	return signing.Profile{ID: id, Name: name, Type: signing.ProfileTypeIOSAppStore, State: signing.ProfileStateActive, BundleID: bundleID, ExpiresAt: expires, CertificateIDs: []string{certificate}}
}

func scenario() (*team, signing.Manifest) {
	portal := &team{
		certificates: []signing.Certificate{
			{ID: "NEW", Type: signing.CertificateTypeDistribution, ExpiresAt: days(365)},
			{ID: "UNUSED", Type: signing.CertificateTypeDistribution, ExpiresAt: days(100)},
			{ID: "FOREIGN", Type: signing.CertificateTypeIOSDistribution, ExpiresAt: days(200)},
		},
		profiles: []signing.Profile{
			profile("CURRENT", "com.example.demo", "com.example.demo", days(365), "NEW"),
			profile("OLDER", "com.example.demo", "com.example.demo", days(50), "UNUSED"),
			profile("DEAD", "Manual profile", "com.example.demo", days(-30), "GONE"),
			profile("LIVE_MANUAL", "Manual live", "com.example.legacy", days(30), "NEW"),
			profile("OTHERS", "Their app", "org.elsewhere", days(30), "FOREIGN"),
		},
	}
	manifest := signing.Manifest{
		Team:     "TEAM123456",
		Profiles: []signing.ProfileSpec{{Kind: signing.AppStore, Name: signing.MustParseTemplate("{bundleId}")}},
		Targets:  []signing.Target{{App: "Demo", Environment: "Production", BundleID: "com.example.demo"}},
		Cleanup:  signing.Scope{Include: []string{"com.example"}},
	}
	return portal, manifest
}

func ids(candidates []signing.ProfileCandidate) []string {
	var result []string
	for _, candidate := range candidates {
		result = append(result, candidate.Profile.ID)
	}
	return result
}

func TestCleanupDeletesOnlyDeadProfiles(t *testing.T) {
	portal, manifest := scenario()
	policy := signing.Policy{Now: now, ExpiryWindow: 45 * 24 * time.Hour}

	plan, err := Prepare(context.Background(), portal, nil, manifest, policy, false)
	if err != nil {
		t.Fatal(err)
	}
	// OLDER is a live namesake CI might still sign with, so it is protected, not even kept for review.
	if !slices.Equal(ids(plan.Delete), []string{"DEAD"}) || !slices.Equal(ids(plan.Keep), []string{"LIVE_MANUAL"}) {
		t.Fatalf("delete = %v, keep = %v", ids(plan.Delete), ids(plan.Keep))
	}
	// UNUSED still signs the live OLDER profile; FOREIGN signs someone else's; NEW is the newest.
	if len(plan.Revocable) != 0 || len(plan.Revoke) != 0 {
		t.Fatalf("revocable = %v", plan.Revocable)
	}

	removed, err := Execute(context.Background(), portal, plan)
	if err != nil || len(removed.Profiles) != 1 || slices.ContainsFunc(portal.profiles, func(profile signing.Profile) bool { return profile.ID == "DEAD" }) {
		t.Fatalf("removed = %+v, %v", removed, err)
	}
}

func TestCertificatesAreRevokedOnlyWhenAskedAndUnused(t *testing.T) {
	portal, manifest := scenario()
	portal.profiles = slices.DeleteFunc(portal.profiles, func(profile signing.Profile) bool { return profile.ID == "OLDER" })
	policy := signing.Policy{Now: now, ExpiryWindow: 45 * 24 * time.Hour}

	vaults := []status.Vault{heldVault{"NEW"}}
	quiet, _ := Prepare(context.Background(), portal, vaults, manifest, policy, false)
	plan, err := Prepare(context.Background(), portal, vaults, manifest, policy, true)

	if err != nil || len(quiet.Revoke) != 0 || len(quiet.Revocable) != 1 || len(plan.Revoke) != 1 || plan.Revoke[0].ID != "UNUSED" {
		t.Fatalf("quiet = %+v, plan = %+v, %v", quiet.Revoke, plan.Revoke, err)
	}
	if _, err := Execute(context.Background(), portal, plan); err != nil || !slices.Equal(portal.revoked, []string{"UNUSED"}) {
		t.Fatalf("revoked = %v, %v", portal.revoked, err)
	}
	if _, err := Prepare(context.Background(), portal, nil, manifest, policy, true); err == nil {
		t.Fatal("planned revocations without knowing which certificates the vaults hold")
	}
}

type heldVault []string

func (heldVault) Describe() string                                 { return "test vault" }
func (v heldVault) List(context.Context, string) ([]string, error) { return v, nil }
