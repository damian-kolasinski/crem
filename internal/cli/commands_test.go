package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/damian-kolasinski/crem/internal/config"
)

func runInFixture(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, config.FileName), []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run(args, Streams{Out: &out, Err: &errOut}, "dev", testEnvironment(t, directory))
	return code, out.String(), errOut.String()
}

func TestConfigJSON(t *testing.T) {
	code, out, errOut := runInFixture(t, "config", "--json")

	if code != 0 || errOut != "" {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	assertGolden(t, "config.json", out)
}

func TestAppsRegisterWithEverythingRegistered(t *testing.T) {
	code, out, _ := runInFixture(t, "apps", "register")

	if code != 0 || out != "Every bundle ID crem.yaml expects is registered (3).\n" {
		t.Fatalf("exit = %d, out = %q", code, out)
	}
}

func TestProfilesDownloadNeedsAKindAndADestination(t *testing.T) {
	for _, testCase := range []struct {
		args []string
		want string
	}{
		{[]string{"profiles", "download", "--output", "x"}, "--kind: unknown profile kind"},
		{[]string{"profiles", "download", "--kind", "ad-hoc"}, "give --output, --install, or both"},
	} {
		code, _, errOut := runInFixture(t, testCase.args...)
		if code != 2 || !strings.Contains(errOut, testCase.want) {
			t.Errorf("%v: exit = %d, stderr = %q", testCase.args, code, errOut)
		}
	}
}
