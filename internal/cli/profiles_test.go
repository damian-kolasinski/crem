package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/damian-kolasinski/crem/internal/config"
)

func TestProfilesRenewDryRun(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, config.FileName), []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer

	code := run([]string{"profiles", "renew"}, Streams{Out: &out, Err: &errOut}, "dev", testEnvironment(t, directory))

	if code != 0 || errOut.String() != "" {
		t.Fatalf("exit = %d, stderr = %q", code, errOut.String())
	}
	assertGolden(t, "profiles-renew-plan.txt", out.String())
}
