package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/certificate"
	"github.com/damian-kolasinski/crem/internal/config"
	"github.com/damian-kolasinski/crem/internal/identity"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/vault"
	"github.com/damian-kolasinski/crem/internal/vault/local"
)

// issuingPortal is a fakePortal that issues real certificates, as Apple would.
type issuingPortal struct {
	fakePortal
	created int
}

func (p *issuingPortal) CreateCertificate(_ context.Context, csrPEM []byte) (signing.Certificate, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return signing.Certificate{}, nil, err
	}
	authority, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "Apple Distribution: Example"}, NotBefore: testNow, NotAfter: day(365)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, request.PublicKey, authority)
	if err != nil {
		return signing.Certificate{}, nil, err
	}
	p.created++
	return signing.Certificate{ID: "CREATED", Name: "Apple Distribution: Example", Type: signing.CertificateTypeDistribution, SerialNumber: "63", ExpiresAt: day(365)}, der, nil
}

func runCert(t *testing.T, issuer *issuingPortal, store vault.Vault, args ...string) (int, string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, config.FileName), []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	env := environment{
		workingDir: directory,
		now:        func() time.Time { return testNow },
		portal:     func(config.Config) (portal, error) { return issuer, nil },
		vaults:     func(config.Config) ([]vault.Vault, error) { return []vault.Vault{store}, nil },
		recovery:   func() certificate.Recovery { return local.NewRecovery(filepath.Join(directory, "recovery")) },
	}
	var out, errOut bytes.Buffer
	code := run(append([]string{"cert", "create"}, args...), Streams{Out: &out, Err: &errOut}, "dev", env)
	return code, out.String(), errOut.String()
}

func TestCertCreateDryRunChangesNothing(t *testing.T) {
	portal := &issuingPortal{fakePortal: fakePortal{snapshot: testSnapshot()}}
	store := local.New("/vaults/team")

	code, out, errOut := runCert(t, portal, store)

	if code != 0 || errOut != "" || portal.created != 0 {
		t.Fatalf("exit = %d, stderr = %q, created = %d", code, errOut, portal.created)
	}
	assertGolden(t, "cert-create-plan.txt", out)
}

func TestCertCreateExecuteSavesTheIdentity(t *testing.T) {
	portal := &issuingPortal{fakePortal: fakePortal{snapshot: testSnapshot()}}
	root := filepath.Join(t.TempDir(), "vault")
	store := local.New(root)

	code, out, errOut := runCert(t, portal, store, "--execute")

	if code != 0 || errOut != "" || portal.created != 1 {
		t.Fatalf("exit = %d, stderr = %q, created = %d", code, errOut, portal.created)
	}
	for _, want := range []string{"Created distribution certificate CREATED (serial 63, expires 2027-10-26)", "Saved the identity to\n  local " + root} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	entry, err := store.Load(context.Background(), "TEAM123456", "CREATED")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Open(entry.P12, entry.Password); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, entry.Password) {
		t.Fatal("the .p12 password was printed")
	}
}

func TestVaultSyncCopiesIntoAnEmptyVault(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, config.FileName), []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	env := testEnvironment(t, directory)
	held, _ := env.vaults(config.Config{})
	empty := local.New(filepath.Join(t.TempDir(), "new"))
	env.vaults = func(config.Config) ([]vault.Vault, error) { return []vault.Vault{held[0], empty}, nil }
	var out, errOut bytes.Buffer

	code := run([]string{"vault", "sync"}, Streams{Out: &out, Err: &errOut}, "dev", env)

	if code != 0 || !strings.Contains(out.String(), "NEWCERT from local ") || !strings.Contains(out.String(), "--execute") {
		t.Fatalf("exit = %d, out = %q, err = %q", code, out.String(), errOut.String())
	}
	if ids, _ := empty.List(context.Background(), "TEAM123456"); len(ids) != 0 {
		t.Fatal("the dry run copied an identity")
	}
}
