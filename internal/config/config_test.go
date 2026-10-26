package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/damian-kolasinski/crem/internal/signing"
)

const valid = `
team: TEAM123456
appStoreConnect:
  keyId: KEY1234567
  issuerId: 00000000-0000-0000-0000-000000000000
  privateKeyEnv: ASC_KEY
profiles:
  - kind: app-store
    name: "{bundleId}"
  - kind: ad-hoc
    name: "AdHoc {bundleId}"
    devices: all
apps:
  - name: Demo
    environments:
      Production: com.example.demo
      Staging: com.example.demo.staging
    extensions: [share]
    secrets:
      app: PROFILE_BASE64_{environment}
  - name: Tool
    environments:
      Production: com.example.tool
`

func TestParseExpandsAppsIntoTargets(t *testing.T) {
	config, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, target := range config.Manifest.Targets {
		got = append(got, target.BundleID+"="+target.Secret)
	}
	want := []string{
		"com.example.demo=PROFILE_BASE64_Production",
		"com.example.demo.share=",
		"com.example.demo.staging=PROFILE_BASE64_Staging",
		"com.example.demo.staging.share=",
		"com.example.tool=",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("targets = %v", got)
	}
	if spec := config.Manifest.Profiles[1]; spec.Kind != signing.AdHoc || spec.Devices != signing.AllDevices {
		t.Fatalf("ad hoc spec = %+v", spec)
	}
	if !config.Manifest.Cleanup.Contains("com.example.demo.staging.share") || config.Manifest.Cleanup.Contains("com.example.other") {
		t.Fatalf("default cleanup scope = %+v", config.Manifest.Cleanup)
	}
	if expected := config.Manifest.ExpectedProfiles(); len(expected) != 10 || expected[1].Name != "AdHoc com.example.demo" {
		t.Fatalf("expected profiles = %d, second = %q", len(expected), expected[1].Name)
	}
}

func TestParseReportsEveryProblem(t *testing.T) {
	_, err := Parse([]byte(`
team: short
appStoreConnect:
  keyId: KEY1234567
profiles:
  - kind: app-store
    name: "Fixed"
  - kind: app-store
    name: "{bundleId}"
    devices: all
apps:
  - name: Demo
    environments:
      Production: demo
      Staging: com.example.demo
    secrets:
      app: SECRET
      watch: OTHER
cleanup:
  include: [org.elsewhere]
`))
	if err == nil {
		t.Fatal("Parse succeeded")
	}
	for _, want := range []string{
		"team: must be a 10-character team ID",
		"appStoreConnect.issuerId: must be the issuer ID",
		"profiles[0].name: must include {bundleId}",
		"profiles[1].kind: app-store is listed twice",
		"profiles[1].devices: only ad-hoc profiles include devices",
		`apps[0].environments.Production: "demo" is not an explicit bundle ID`,
		"apps[0].secrets.app: must include {environment}",
		`apps[0].secrets.watch: not "app" or one of the app's extensions`,
		"cleanup: managed bundle ID com.example.demo is outside the cleanup scope",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestParseRejectsDuplicatesAndEmptyFiles(t *testing.T) {
	cases := map[string]string{
		"environment \"Production\" is listed twice": strings.Replace(valid, "      Staging: com.example.demo.staging", "      Production: com.example.demo.staging", 1),
		"would both use the secret PROFILE": strings.Replace(strings.Replace(valid, "PROFILE_BASE64_{environment}", "PROFILE", 1), "      Staging: com.example.demo.staging\n", "", 1) +
			"    secrets:\n      app: PROFILE\n",
		"the file is empty": "",
	}
	for want, source := range cases {
		if _, err := Parse([]byte(source)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(valid + "surprise: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestFindWalksUpToTheNearestConfig(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, FileName), []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}

	path, err := Find(nested)

	if err != nil || path != filepath.Join(root, FileName) {
		t.Fatalf("Find = %q, %v", path, err)
	}
	if _, err := Find(t.TempDir()); err == nil {
		t.Fatal("Find succeeded without a config")
	}
}

func TestPrivateKeyLookupOrder(t *testing.T) {
	home := t.TempDir()
	configDir := t.TempDir()
	keyDir := filepath.Join(home, ".appstoreconnect", "private_keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "AuthKey_KEY1234567.p8"), []byte("from-home"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "key.p8"), []byte("from-path"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ASC_KEY": `line1\nline2`}
	environment := Environment{Getenv: func(name string) string { return env[name] }, HomeDir: home, WorkingDir: t.TempDir(), ConfigDir: configDir}

	cases := []struct {
		name   string
		source AppStoreConnect
		want   string
	}{
		{"environment variable wins", AppStoreConnect{KeyID: "KEY1234567", PrivateKeyEnv: "ASC_KEY", PrivateKeyPath: "key.p8"}, "line1\nline2"},
		{"unset variable falls back to path", AppStoreConnect{KeyID: "KEY1234567", PrivateKeyEnv: "UNSET", PrivateKeyPath: "key.p8"}, "from-path"},
		{"default directories", AppStoreConnect{KeyID: "KEY1234567"}, "from-home"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key, _, err := testCase.source.PrivateKey(environment)
			if err != nil || string(key) != testCase.want {
				t.Fatalf("PrivateKey = %q, %v", key, err)
			}
		})
	}

	_, _, err := AppStoreConnect{KeyID: "MISSING123", PrivateKeyEnv: "UNSET"}.PrivateKey(environment)
	if err == nil || !strings.Contains(err.Error(), "$UNSET") || !strings.Contains(err.Error(), "AuthKey_MISSING123.p8") {
		t.Fatalf("err = %v", err)
	}
}
