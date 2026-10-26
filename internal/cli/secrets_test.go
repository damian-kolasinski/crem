package cli

import (
	"bytes"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/publish"
	"github.com/damian-kolasinski/crem/internal/signing"
)

func TestSecretsPushPlanOutput(t *testing.T) {
	plan := publish.Plan{
		Certificate:  signing.Certificate{ID: "NEWCERT", ExpiresAt: day(365)},
		Fingerprint:  "0123456789ABCDEF0123456789ABCDEF01234567",
		IdentityFrom: "local /vaults/team",
		Secrets: []publish.Secret{
			{Name: "CERTIFICATE_BASE64", Description: ".p12 of NEWCERT"},
			{Name: "CERTIFICATE_PASSWORD", Description: "its password"},
			{Name: "PROFILE_DEMO", Description: "com.example.demo (P9, expires 2027-10-26)"},
		},
		Stores:  []string{"GitHub owner/app"},
		Updated: map[string]map[string]time.Time{"GitHub owner/app": {"CERTIFICATE_BASE64": day(-300), "PROFILE_DEMO": day(-300)}},
	}
	var out bytes.Buffer

	if err := renderPushPlan(&out, plan); err != nil {
		t.Fatal(err)
	}

	assertGolden(t, "secrets-push-plan.txt", out.String())
}

func TestGitHubTokenPrefersTheConfiguredVariable(t *testing.T) {
	env := environment{getenv: func(name string) string {
		return map[string]string{"CI_TOKEN": "configured", "GH_TOKEN": "default"}[name]
	}}
	if token, err := gitHubToken(env, "CI_TOKEN"); err != nil || token != "configured" {
		t.Fatalf("token = %q, %v", token, err)
	}
	if token, err := gitHubToken(env, ""); err != nil || token != "default" {
		t.Fatalf("token = %q, %v", token, err)
	}
	if _, err := gitHubToken(env, "UNSET"); err == nil {
		t.Fatal("accepted an empty configured variable")
	}
}
