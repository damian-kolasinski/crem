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
certificate:
  secrets:
    p12: CERTIFICATE_BASE64
    password: CERTIFICATE_PASSWORD
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
		"com.example.demo=PROFILE_BASE64_PRODUCTION",
		"com.example.demo.share=",
		"com.example.demo.staging=PROFILE_BASE64_STAGING",
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
		"appStoreConnect: set exactly one of issuerId or issuerIdEnv",
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
		"would both use the secret PROFILE": strings.Replace(strings.Replace(strings.Replace(valid, "PROFILE_BASE64_{environment}", "PROFILE", 1), "      Staging: com.example.demo.staging\n", "", 1),
			"      Production: com.example.tool\n", "      Production: com.example.tool\n    secrets:\n      app: PROFILE\n", 1),
		"the file is empty": "",
	}
	for want, source := range cases {
		if _, err := Parse([]byte(source)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestSecrets(t *testing.T) {
	config, err := Parse([]byte(valid + `
secretStores:
  - github:
      repository: owner/app
      environment: Production
`))
	if err != nil {
		t.Fatal(err)
	}
	if config.CertificateSecrets.P12 != "CERTIFICATE_BASE64" || config.SecretStores[0].GitHub.Environment != "Production" {
		t.Fatalf("secrets = %+v, stores = %+v", config.CertificateSecrets, config.SecretStores)
	}

	withoutCertificate := strings.Replace(valid, "certificate:\n  secrets:\n    p12: CERTIFICATE_BASE64\n    password: CERTIFICATE_PASSWORD\n", "", 1)
	broken := strings.Replace(valid, "password: CERTIFICATE_PASSWORD", "password: PROFILE_BASE64_Staging", 1) + `
secretStores:
  - github:
      repository: not-a-repository
`
	for source, want := range map[string]string{
		withoutCertificate: "certificate.secrets: required because com.example.demo pushes its profile",
		broken:             "certificate.secrets: PROFILE_BASE64_STAGING is also the profile secret of com.example.demo.staging",
	} {
		if _, err := Parse([]byte(source)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	if _, err := Parse([]byte(broken)); err == nil || !strings.Contains(err.Error(), "secretStores[0].github.repository: must be owner/name") {
		t.Errorf("repository: %v", err)
	}
	reserved := strings.Replace(valid, "p12: CERTIFICATE_BASE64", "p12: github_certificate", 1)
	if _, err := Parse([]byte(reserved)); err == nil || !strings.Contains(err.Error(), `"GITHUB_CERTIFICATE" is not a valid secret name`) {
		t.Errorf("reserved prefix: %v", err)
	}
	adHocOnly := strings.Replace(valid, "  - kind: app-store\n    name: \"{bundleId}\"\n", "", 1)
	if _, err := Parse([]byte(adHocOnly)); err == nil || !strings.Contains(err.Error(), "profiles must include the app-store kind") {
		t.Errorf("secrets without app-store profiles: %v", err)
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

func TestIDsFromTheEnvironment(t *testing.T) {
	source := strings.Replace(strings.Replace(valid, "  keyId: KEY1234567\n", "  keyIdEnv: ASC_KEY_ID\n", 1), "  issuerId: 00000000-0000-0000-0000-000000000000\n", "  issuerIdEnv: ASC_ISSUER\n", 1)
	config, err := Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ASC_KEY_ID": "KEY7654321", "ASC_ISSUER": "11111111-2222-3333-4444-555555555555"}
	resolved, err := config.AppStoreConnect.Resolve(Environment{Getenv: func(name string) string { return env[name] }})
	if err != nil || resolved.KeyID != "KEY7654321" || resolved.IssuerID != env["ASC_ISSUER"] {
		t.Fatalf("resolved = %+v, %v", resolved, err)
	}
	if _, err := config.AppStoreConnect.Resolve(Environment{Getenv: func(string) string { return "" }}); err == nil || !strings.Contains(err.Error(), "$ASC_KEY_ID must be a 10-character API key ID") {
		t.Fatalf("unset variable: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(valid, "  keyId: KEY1234567\n", "  keyId: KEY1234567\n  keyIdEnv: ASC_KEY_ID\n", 1))); err == nil || !strings.Contains(err.Error(), "set exactly one of keyId or keyIdEnv") {
		t.Fatalf("both: %v", err)
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
	if err := os.WriteFile(filepath.Join(configDir, "AuthKey_KEY1234567.p8"), []byte("from-path"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ASC_KEY": `line1\nline2`}
	environment := Environment{Getenv: func(name string) string { return env[name] }, HomeDir: home, WorkingDir: t.TempDir(), ConfigDir: configDir}

	cases := []struct {
		name   string
		source AppStoreConnect
		want   string
	}{
		{"environment variable wins", AppStoreConnect{KeyID: "KEY1234567", PrivateKeyEnv: "ASC_KEY", PrivateKeyPath: "AuthKey_{keyId}.p8"}, "line1\nline2"},
		{"unset variable falls back to path", AppStoreConnect{KeyID: "KEY1234567", PrivateKeyEnv: "UNSET", PrivateKeyPath: "AuthKey_{keyId}.p8"}, "from-path"},
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

func TestVaults(t *testing.T) {
	config, err := Parse([]byte(valid + `
vaults:
  - local: {}
  - local:
      path: ~/signing
  - 1password:
      vault: Mobile
      account: work
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Vaults) != 3 || config.Vaults[1].Local.Path != "~/signing" || config.Vaults[2].OnePassword.Account != "work" {
		t.Fatalf("vaults = %+v", config.Vaults)
	}

	_, err = Parse([]byte(valid + `
vaults:
  - local: {}
    1password: {vault: Mobile}
  - 1password: {}
`))
	for _, want := range []string{"vaults[0]: set exactly one of local or 1password", "vaults[1].1password.vault: name the 1Password vault"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestLocalVaultDirectoryStaysOutsideTheRepository(t *testing.T) {
	home, _ := filepath.EvalSymlinks(t.TempDir())
	repository, _ := filepath.EvalSymlinks(t.TempDir())
	configDir := filepath.Join(repository, "ios")
	for _, directory := range []string{filepath.Join(repository, ".git"), configDir} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(home, "sneaky")
	if err := os.Symlink(repository, link); err != nil {
		t.Fatal(err)
	}
	environment := Environment{HomeDir: home, ConfigDir: configDir}

	if directory, err := (LocalVault{}).Directory("TEAM123456", environment); err != nil || directory != filepath.Join(home, ".crem", "TEAM123456") {
		t.Fatalf("default = %q, %v", directory, err)
	}
	upperRepository := filepath.Join(filepath.Dir(repository), strings.ToUpper(filepath.Base(repository)))
	if _, err := os.Stat(upperRepository); err == nil {
		// Case-insensitive file system: a differently cased path must still be caught.
		if _, err := (LocalVault{Path: filepath.Join(upperRepository, "vault")}).Directory("TEAM123456", environment); err == nil {
			t.Error("accepted a differently cased path into the repository")
		}
	}
	for _, inside := range []string{"signing", "../secrets", "~/sneaky/vault"} {
		if _, err := (LocalVault{Path: inside}).Directory("TEAM123456", environment); err == nil || !strings.Contains(err.Error(), "inside the repository") {
			t.Errorf("%s: err = %v", inside, err)
		}
	}
}
