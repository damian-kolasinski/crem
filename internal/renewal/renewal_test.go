package renewal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/status"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

// team is an in-memory App Store Connect team.
type team struct {
	certificates []signing.Certificate
	bundleIDs    []signing.BundleID
	profiles     []signing.Profile
	devices      []signing.Device
	// profileDevices holds each profile's device IDs.
	profileDevices map[string][]string
}

func (t *team) Certificates(context.Context) ([]signing.Certificate, error) {
	return t.certificates, nil
}
func (t *team) BundleIDs(context.Context) ([]signing.BundleID, error) { return t.bundleIDs, nil }
func (t *team) Profiles(context.Context) ([]signing.Profile, error)   { return t.profiles, nil }
func (t *team) AdHocDevices(context.Context) ([]signing.Device, error) {
	var enabled []signing.Device
	for _, device := range t.devices {
		if device.Class != "DISABLED" {
			enabled = append(enabled, device)
		}
	}
	return enabled, nil
}
func (t *team) ProfileDevices(_ context.Context, id string) ([]signing.Device, error) {
	var devices []signing.Device
	for _, device := range t.devices {
		if slices.Contains(t.profileDevices[id], device.ID) {
			devices = append(devices, device)
		}
	}
	return devices, nil
}
func (t *team) DeleteProfile(_ context.Context, id string) error {
	index := slices.IndexFunc(t.profiles, func(profile signing.Profile) bool { return profile.ID == id })
	if index < 0 {
		return fmt.Errorf("profile %s not found", id)
	}
	t.profiles = slices.Delete(t.profiles, index, index+1)
	return nil
}

func (t *team) CreateProfile(_ context.Context, request signing.NewProfile) (signing.Profile, error) {
	if !slices.ContainsFunc(t.bundleIDs, func(bundleID signing.BundleID) bool { return bundleID.Identifier == request.BundleID }) {
		return signing.Profile{}, fmt.Errorf("bundle ID %s is not registered", request.BundleID)
	}
	// Like App Store Connect may, refuse a name that is already taken.
	if slices.ContainsFunc(t.profiles, func(profile signing.Profile) bool {
		return profile.Name == request.Name && profile.ExpiresAt.Before(now)
	}) {
		return signing.Profile{}, fmt.Errorf("multiple profiles found with the name %q", request.Name)
	}
	profile := signing.Profile{
		ID: fmt.Sprintf("NEW%d", len(t.profiles)), Name: request.Name, Type: request.Type, State: signing.ProfileStateActive,
		BundleID: request.BundleID, CreatedAt: now, ExpiresAt: days(365), CertificateIDs: []string{request.CertificateID},
	}
	t.profiles = append(t.profiles, profile)
	t.profileDevices[profile.ID] = request.DeviceIDs
	return profile, nil
}

type heldVault []string

func (heldVault) Describe() string                                 { return "test vault" }
func (v heldVault) List(context.Context, string) ([]string, error) { return v, nil }

func manifest(devices signing.DeviceSelection) signing.Manifest {
	return signing.Manifest{
		Team: "TEAM123456",
		Profiles: []signing.ProfileSpec{
			{Kind: signing.AppStore, Name: signing.MustParseTemplate("{bundleId}")},
			{Kind: signing.AdHoc, Name: signing.MustParseTemplate("AdHoc {bundleId}"), Devices: devices},
		},
		Targets: []signing.Target{
			{App: "Demo", Environment: "Production", BundleID: "com.example.demo"},
			{App: "Demo", Environment: "Production", Extension: "share", BundleID: "com.example.demo.share"},
		},
		Cleanup: signing.Scope{Include: []string{"com.example"}},
	}
}

// expiredTeam is a team whose old certificate expired and took the profiles with it.
// The share extension never had an Ad Hoc profile.
func expiredTeam() *team {
	return &team{
		certificates: []signing.Certificate{
			{ID: "NEWCERT", Type: signing.CertificateTypeDistribution, ExpiresAt: days(365)},
			{ID: "FOREIGN", Type: signing.CertificateTypeIOSDistribution, ExpiresAt: days(400)},
		},
		bundleIDs: []signing.BundleID{{Identifier: "com.example.demo"}, {Identifier: "com.example.demo.share"}},
		profiles: []signing.Profile{
			{ID: "OLD1", Name: "com.example.demo", Type: signing.ProfileTypeIOSAppStore, State: signing.ProfileStateActive, BundleID: "com.example.demo", ExpiresAt: days(-2), CertificateIDs: []string{"OLDCERT"}},
			{ID: "OLD2", Name: "AdHoc com.example.demo", Type: signing.ProfileTypeIOSAdHoc, State: signing.ProfileStateActive, BundleID: "com.example.demo", ExpiresAt: days(-2), CertificateIDs: []string{"OLDCERT"}},
		},
		devices:        []signing.Device{{ID: "D1", Class: "IPHONE"}, {ID: "D2", Class: "IPAD"}, {ID: "D3", Class: "DISABLED"}, {ID: "D4", Class: "IPHONE"}},
		profileDevices: map[string][]string{"OLD2": {"D1", "D2", "D3"}},
	}
}

func policy() signing.Policy { return signing.Policy{Now: now, ExpiryWindow: 45 * 24 * time.Hour} }

func TestRenewalCarriesDevicesOverAndConverges(t *testing.T) {
	ctx := context.Background()
	portal := expiredTeam()
	vaults := []status.Vault{heldVault{"NEWCERT"}}

	plan, err := Prepare(ctx, portal, vaults, manifest(signing.CarryOverDevices), policy(), "")
	if err != nil {
		t.Fatal(err)
	}

	if plan.Certificate.ID != "NEWCERT" {
		t.Fatalf("signing certificate = %s; the foreign one expires later but no vault holds it", plan.Certificate.ID)
	}
	var items []string
	for _, item := range plan.Items {
		var devices []string
		for _, device := range item.Devices {
			devices = append(devices, device.ID)
		}
		items = append(items, fmt.Sprintf("%s (%s) %v", item.Expected.Name, item.Reason, devices))
	}
	want := []string{"com.example.demo (expired) []", "AdHoc com.example.demo (expired) [D1 D2]", "com.example.demo.share (missing) []"}
	if !slices.Equal(items, want) {
		t.Fatalf("items = %v", items)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Reason != signing.SkipNoDeviceSource {
		t.Fatalf("skipped = %v", plan.Skipped)
	}

	created, err := Execute(ctx, portal, plan)
	if err != nil || len(created) != 3 {
		t.Fatalf("created = %v, %v", created, err)
	}
	if len(created[0].Removed) != 1 || created[0].Removed[0].ID != "OLD1" || slices.ContainsFunc(portal.profiles, func(profile signing.Profile) bool { return profile.ID == "OLD1" }) {
		t.Fatalf("the expired namesake was not deleted first: %v", created[0].Removed)
	}
	again, err := Prepare(ctx, portal, vaults, manifest(signing.CarryOverDevices), policy(), "")
	if err != nil || len(again.Items) != 0 || again.UpToDate != 3 {
		t.Fatalf("second plan = %+v, %v", again, err)
	}
}

func TestAllDevicesSelection(t *testing.T) {
	plan, err := Prepare(context.Background(), expiredTeam(), []status.Vault{heldVault{"NEWCERT"}}, manifest(signing.AllDevices), policy(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 4 || len(plan.Skipped) != 0 || len(plan.Items[3].Devices) != 3 {
		t.Fatalf("plan = %+v", plan)
	}
}

type lockedVault struct{}

func (lockedVault) Describe() string                               { return "locked vault" }
func (lockedVault) List(context.Context, string) ([]string, error) { return nil, errors.New("locked") }

func TestPrepareRefusesWithoutAHeldCertificate(t *testing.T) {
	ctx := context.Background()
	if _, err := Prepare(ctx, expiredTeam(), []status.Vault{heldVault{}}, manifest(signing.AllDevices), policy(), ""); err == nil || !strings.Contains(err.Error(), "FOREIGN is valid but its identity is not in a vault") {
		t.Fatalf("planned without a certificate held in a vault: %v", err)
	}
	if _, err := Prepare(ctx, expiredTeam(), []status.Vault{heldVault{"NEWCERT"}, lockedVault{}}, manifest(signing.AllDevices), policy(), ""); err == nil || !strings.Contains(err.Error(), "every vault must be readable") {
		t.Fatalf("planned with a locked vault: %v", err)
	}
	if _, err := Prepare(ctx, expiredTeam(), nil, manifest(signing.AllDevices), policy(), ""); err == nil {
		t.Fatal("planned without vaults")
	}
	if _, err := Prepare(ctx, expiredTeam(), []status.Vault{heldVault{"NEWCERT"}}, manifest(signing.AllDevices), policy(), "FOREIGN"); err == nil || !strings.Contains(err.Error(), "no vault holds") {
		t.Fatalf("explicit foreign certificate = %v", err)
	}
}

func TestExecuteStopsAtTheFirstFailure(t *testing.T) {
	portal := expiredTeam()
	plan, _ := Prepare(context.Background(), portal, []status.Vault{heldVault{"NEWCERT"}}, manifest(signing.AllDevices), policy(), "")
	portal.bundleIDs = portal.bundleIDs[:1]

	created, err := Execute(context.Background(), portal, plan)

	if err == nil || len(created) != 2 || !strings.Contains(err.Error(), "creating com.example.demo.share") {
		t.Fatalf("created = %d, err = %v", len(created), err)
	}
}
