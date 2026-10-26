package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlagPrintsVersion(t *testing.T) {
	var out, errOut bytes.Buffer

	code := Run([]string{"--version"}, Streams{Out: &out, Err: &errOut}, "1.2.3")

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	if got := strings.TrimSpace(out.String()); got != "crem version 1.2.3" {
		t.Fatalf("output = %q", got)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	var out, errOut bytes.Buffer

	code := Run([]string{"nope"}, Streams{Out: &out, Err: &errOut}, "dev")

	if code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.HasPrefix(errOut.String(), "crem: unknown command \"nope\"") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}
