package download

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	"github.com/damian-kolasinski/crem/internal/signing"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

type team struct {
	profiles []signing.Profile
	content  map[string][]byte
}

func (t *team) Profiles(context.Context) ([]signing.Profile, error) { return t.profiles, nil }
func (t *team) ProfileContent(_ context.Context, id string) ([]byte, error) {
	return t.content[id], nil
}

// profileFile signs a profile property list the way Apple does.
func profileFile(t *testing.T, name, bundleID string, devices bool) []byte {
	t.Helper()
	return profileFileWithUUID(t, name, bundleID, devices, "UUID-"+name)
}

func profileFileWithUUID(t *testing.T, name, bundleID string, devices bool, uuid string) []byte {
	t.Helper()
	content := map[string]any{
		"Name":           name,
		"UUID":           uuid,
		"TeamIdentifier": []string{"TEAM123456"},
		"ExpirationDate": days(300),
		"Entitlements":   map[string]any{"application-identifier": "TEAM123456." + bundleID},
	}
	if devices {
		content["ProvisionedDevices"] = []string{"00008110-0001"}
	}
	data, _ := plist.Marshal(content, plist.XMLFormat)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now, NotAfter: days(365)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	signer, _ := x509.ParseCertificate(der)
	signed, _ := pkcs7.NewSignedData(data)
	if err := signed.AddSigner(signer, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	result, _ := signed.Finish()
	return result
}

func manifest() signing.Manifest {
	return signing.Manifest{
		Team: "TEAM123456",
		Profiles: []signing.ProfileSpec{
			{Kind: signing.AppStore, Name: signing.MustParseTemplate("{bundleId}")},
			{Kind: signing.AdHoc, Name: signing.MustParseTemplate("AdHoc {bundleId}"), Devices: signing.CarryOverDevices},
		},
		Targets: []signing.Target{
			{App: "Demo", Environment: "Staging", BundleID: "com.example.demo.staging"},
			{App: "Demo", Environment: "Staging", Extension: "share", BundleID: "com.example.demo.staging.share"},
			{App: "Demo", Environment: "Production", BundleID: "com.example.demo"},
		},
		Cleanup: signing.Scope{Include: []string{"com.example"}},
	}
}

func adHoc(id, bundleID string, expires time.Time) signing.Profile {
	return signing.Profile{ID: id, Name: "AdHoc " + bundleID, Type: signing.ProfileTypeIOSAdHoc, State: signing.ProfileStateActive, UUID: "UUID-AdHoc " + bundleID, BundleID: bundleID, ExpiresAt: expires}
}

func scenario(t *testing.T) *team {
	return &team{
		profiles: []signing.Profile{
			adHoc("OLD", "com.example.demo.staging", days(-1)),
			adHoc("NEW", "com.example.demo.staging", days(300)),
			adHoc("SHARE", "com.example.demo.staging.share", days(300)),
		},
		content: map[string][]byte{
			"NEW":   profileFile(t, "AdHoc com.example.demo.staging", "com.example.demo.staging", true),
			"SHARE": profileFile(t, "AdHoc com.example.demo.staging.share", "com.example.demo.staging.share", true),
		},
	}
}

func TestDownloadsTheCurrentProfilesOfAnEnvironment(t *testing.T) {
	first, second := t.TempDir(), filepath.Join(t.TempDir(), "nested")
	portal := scenario(t)

	downloaded, err := Run(context.Background(), portal, manifest(), Selection{Kind: signing.AdHoc, App: "Demo", Environment: "Staging"}, Destinations{Outputs: []string{first, second}}, now)

	if err != nil || len(downloaded) != 2 || downloaded[0].Profile.ID != "NEW" {
		t.Fatalf("downloaded = %+v, %v", downloaded, err)
	}
	for _, directory := range []string{first, second} {
		files, _ := filepath.Glob(filepath.Join(directory, "*.mobileprovision"))
		if len(files) != 2 {
			t.Fatalf("%s holds %v", directory, files)
		}
	}
	written, _ := os.ReadFile(downloaded[1].Paths[1])
	if string(written) != string(portal.content["SHARE"]) || filepath.Base(downloaded[1].Paths[1]) != "UUID-AdHoc com.example.demo.staging.share.mobileprovision" {
		t.Fatalf("wrote %s with other contents", downloaded[1].Paths[1])
	}
}

func TestDownloadsNothingUnlessEveryProfileIsLive(t *testing.T) {
	portal := scenario(t)
	portal.profiles = portal.profiles[:2]
	directory := t.TempDir()

	_, err := Run(context.Background(), portal, manifest(), Selection{Kind: signing.AdHoc, Environment: "Staging"}, Destinations{Outputs: []string{directory}}, now)

	if err == nil || !strings.Contains(err.Error(), "no live profile for AdHoc com.example.demo.staging.share") {
		t.Fatalf("err = %v", err)
	}
	if files, _ := filepath.Glob(filepath.Join(directory, "*")); len(files) != 0 {
		t.Fatalf("wrote %v", files)
	}
}

func TestRefusesAProfileThatIsNotTheExpectedOne(t *testing.T) {
	portal := scenario(t)
	portal.content["SHARE"] = profileFile(t, "AdHoc com.example.demo.staging.share", "com.example.other", true)

	_, err := Run(context.Background(), portal, manifest(), Selection{Kind: signing.AdHoc, Environment: "Staging"}, Destinations{Outputs: []string{t.TempDir()}}, now)

	if err == nil || !strings.Contains(err.Error(), "is for com.example.other") {
		t.Fatalf("err = %v", err)
	}
}

func TestSelectionMustMatchTheConfig(t *testing.T) {
	cases := map[string]Selection{
		"expects no ad-hoc profile for that selection":  {Kind: signing.AdHoc, App: "Other"},
		"expects no ad-hoc profile for com.example.zzz": {Kind: signing.AdHoc, BundleIDs: []string{"com.example.demo.staging", "com.example.zzz"}},
	}
	for want, selection := range cases {
		if _, err := Run(context.Background(), scenario(t), manifest(), selection, Destinations{Outputs: []string{t.TempDir()}}, now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestInstallReplacesStaleProfilesWithTheSameName(t *testing.T) {
	install := t.TempDir()
	stale := filepath.Join(install, "STALE.mobileprovision")
	other := filepath.Join(install, "OTHER.mobileprovision")
	junk := filepath.Join(install, "JUNK.mobileprovision")
	os.WriteFile(stale, profileFileWithUUID(t, "AdHoc com.example.demo.staging", "com.example.demo.staging", true, "STALE"), 0o644)
	os.WriteFile(other, profileFileWithUUID(t, "Someone else's", "com.example.demo.staging", true, "OTHER"), 0o644)
	os.WriteFile(junk, []byte("not a profile"), 0o644)

	downloaded, err := Run(context.Background(), scenario(t), manifest(), Selection{Kind: signing.AdHoc, Environment: "Staging"}, Destinations{Installs: []string{install}}, now)

	if err != nil || len(downloaded[0].Replaced) != 1 || downloaded[0].Replaced[0] != stale {
		t.Fatalf("downloaded = %+v, %v", downloaded, err)
	}
	for path, kept := range map[string]bool{stale: false, other: true, junk: true} {
		if _, err := os.Stat(path); (err == nil) != kept {
			t.Errorf("%s kept = %v, want %v", filepath.Base(path), err == nil, kept)
		}
	}
}

func TestRefusesAFileWhoseUUIDIsNotTheProfiles(t *testing.T) {
	portal := scenario(t)
	portal.content["NEW"] = profileFileWithUUID(t, "AdHoc com.example.demo.staging", "com.example.demo.staging", true, "SOMETHING-ELSE")

	_, err := Run(context.Background(), portal, manifest(), Selection{Kind: signing.AdHoc, Environment: "Staging"}, Destinations{Outputs: []string{t.TempDir()}}, now)

	if err == nil || !strings.Contains(err.Error(), "has UUID SOMETHING-ELSE") {
		t.Fatalf("err = %v", err)
	}
}
