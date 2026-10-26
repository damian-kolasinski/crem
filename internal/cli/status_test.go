package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/config"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/vault"
	"github.com/damian-kolasinski/crem/internal/vault/local"
)

var update = flag.Bool("update", false, "rewrite golden files")

var testNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

const testConfig = `
team: TEAM123456
appStoreConnect:
  keyId: KEY1234567
  issuerId: 00000000-0000-0000-0000-000000000000
profiles:
  - kind: app-store
    name: "{bundleId}"
  - kind: ad-hoc
    name: "AdHoc {bundleId}"
apps:
  - name: Demo
    environments:
      Production: com.example.demo
    extensions: [share]
    secrets:
      app: PROFILE_DEMO
  - name: Tool
    environments:
      Production: com.example.tool
certificate:
  secrets:
    p12: CERTIFICATE_BASE64
    password: CERTIFICATE_PASSWORD
cleanup:
  include: [com.example]
`

type fakePortal struct{ snapshot signing.Snapshot }

func (p fakePortal) Certificates(context.Context) ([]signing.Certificate, error) {
	return p.snapshot.Certificates, nil
}
func (p fakePortal) BundleIDs(context.Context) ([]signing.BundleID, error) {
	return p.snapshot.BundleIDs, nil
}
func (p fakePortal) Profiles(context.Context) ([]signing.Profile, error) {
	return p.snapshot.Profiles, nil
}
func (p fakePortal) AdHocDevices(context.Context) ([]signing.Device, error) {
	return p.snapshot.AdHocDevices, nil
}
func (p fakePortal) CreateCertificate(context.Context, []byte) (signing.Certificate, []byte, error) {
	return signing.Certificate{}, nil, errors.New("not implemented")
}
func (p fakePortal) CreateProfile(context.Context, signing.NewProfile) (signing.Profile, error) {
	return signing.Profile{}, errors.New("not implemented")
}
func (p fakePortal) ProfileContent(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (p fakePortal) RevokeCertificate(context.Context, string) error {
	return errors.New("not implemented")
}
func (p fakePortal) BundleIDCapabilities(context.Context, string) ([]signing.Capability, error) {
	return nil, nil
}
func (p fakePortal) RegisterBundleID(context.Context, string, string) error {
	return errors.New("not implemented")
}
func (p fakePortal) EnableCapability(context.Context, string, signing.Capability) error {
	return errors.New("not implemented")
}
func (p fakePortal) DeleteProfile(context.Context, string) error {
	return errors.New("not implemented")
}
func (p fakePortal) ProfileDevices(_ context.Context, id string) ([]signing.Device, error) {
	var devices []signing.Device
	for _, deviceID := range p.snapshot.ProfileDevices[id] {
		devices = append(devices, signing.Device{ID: deviceID})
	}
	return devices, nil
}

func day(n int) time.Time { return testNow.Add(time.Duration(n) * 24 * time.Hour) }

func testProfile(id, name string, kind signing.ProfileType, bundleID string, expires time.Time, certificates ...string) signing.Profile {
	return signing.Profile{ID: id, Name: name, Type: kind, State: signing.ProfileStateActive, BundleID: bundleID, CreatedAt: expires.AddDate(-1, 0, 0), ExpiresAt: expires, CertificateIDs: certificates}
}

// A team whose old certificate expired: Demo's profiles died with it, Tool was already renewed.
func testSnapshot() signing.Snapshot {
	return signing.Snapshot{
		Certificates: []signing.Certificate{
			{ID: "NEWCERT", Name: "Apple Distribution: Example", Type: signing.CertificateTypeDistribution, SerialNumber: "AB12", ExpiresAt: day(340)},
			{ID: "DEVCERT", Name: "Apple Development: Someone", Type: "DEVELOPMENT", ExpiresAt: day(200)},
		},
		BundleIDs: []signing.BundleID{{Identifier: "com.example.demo"}, {Identifier: "com.example.demo.share"}, {Identifier: "com.example.tool"}},
		Profiles: []signing.Profile{
			testProfile("P1", "com.example.demo", signing.ProfileTypeIOSAppStore, "com.example.demo", day(-2), "OLDCERT"),
			testProfile("P2", "AdHoc com.example.demo", signing.ProfileTypeIOSAdHoc, "com.example.demo", day(-2), "OLDCERT"),
			testProfile("P3", "com.example.tool", signing.ProfileTypeIOSAppStore, "com.example.tool", day(340), "NEWCERT"),
			testProfile("P4", "AdHoc com.example.tool", signing.ProfileTypeIOSAdHoc, "com.example.tool", day(340), "NEWCERT"),
			testProfile("P5", "Old manual profile", signing.ProfileTypeIOSAppStore, "com.example.legacy", day(-100), "OLDCERT"),
			testProfile("P6", "Someone else's", signing.ProfileTypeIOSAppStore, "org.elsewhere", day(100), "NEWCERT"),
		},
		AdHocDevices:   []signing.Device{{ID: "D1"}, {ID: "D2"}, {ID: "D3"}},
		ProfileDevices: map[string][]string{"P2": {"D1", "D3", "RETIRED"}, "P4": {"D1", "D2", "RETIRED"}},
	}
}

func runStatus(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, config.FileName), []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run(append([]string{"status"}, args...), Streams{Out: &out, Err: &errOut}, "dev", testEnvironment(t, directory))
	return code, out.String(), errOut.String()
}

// testEnvironment reaches the fixture team, with a vault holding NEWCERT's identity.
func testEnvironment(t *testing.T, directory string) environment {
	t.Helper()
	store := local.New(filepath.Join(t.TempDir(), "vault"))
	if err := store.Save(context.Background(), vault.Entry{Team: "TEAM123456", CertificateID: "NEWCERT", P12: []byte("p12"), Password: "password"}); err != nil {
		t.Fatal(err)
	}
	return environment{
		workingDir: directory,
		homeDir:    t.TempDir(),
		getenv:     func(string) string { return "" },
		now:        func() time.Time { return testNow },
		portal: func(config.Config) (portal, error) {
			return fakePortal{snapshot: testSnapshot()}, nil
		},
		vaults: func(config.Config) ([]vault.Vault, error) { return []vault.Vault{store}, nil },
	}
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s differs (run go test ./internal/cli -update to accept):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestStatusReport(t *testing.T) {
	code, out, errOut := runStatus(t)

	if code != 0 || errOut != "" {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	assertGolden(t, "status.txt", out)
}

func TestStatusJSON(t *testing.T) {
	code, out, errOut := runStatus(t, "--json")

	if code != 0 || errOut != "" {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	assertGolden(t, "status.json", out)
}

func TestStatusCheckExitsThreeWhenActionIsNeeded(t *testing.T) {
	code, _, errOut := runStatus(t, "--check")

	if code != exitNeedsAction || errOut != "" {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
}

func TestStatusWithoutConfigFails(t *testing.T) {
	var out, errOut bytes.Buffer
	env := environment{workingDir: t.TempDir(), now: func() time.Time { return testNow }}

	code := run([]string{"status"}, Streams{Out: &out, Err: &errOut}, "dev", env)

	if code != 1 || !bytes.Contains(errOut.Bytes(), []byte("no crem.yaml in")) {
		t.Fatalf("exit = %d, stderr = %q", code, errOut.String())
	}
}
