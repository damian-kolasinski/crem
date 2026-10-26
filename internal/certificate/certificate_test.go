package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/identity"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/vault"
	"github.com/damian-kolasinski/crem/internal/vault/local"
)

// fakePortal issues real certificates for the CSRs it receives, as Apple would.
type fakePortal struct {
	existing []signing.Certificate
	created  []string
}

func (p *fakePortal) Certificates(context.Context) ([]signing.Certificate, error) {
	return p.existing, nil
}

func (p *fakePortal) CreateCertificate(_ context.Context, csrPEM []byte) (signing.Certificate, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return signing.Certificate{}, nil, err
	}
	authority, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Apple Distribution"}, NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, request.PublicKey, authority)
	if err != nil {
		return signing.Certificate{}, nil, err
	}
	id := "NEW" + string(rune('0'+len(p.created)))
	p.created = append(p.created, id)
	return signing.Certificate{ID: id, Type: signing.CertificateTypeDistribution, SerialNumber: "07", ExpiresAt: template.NotAfter}, der, nil
}

type brokenVault struct{}

func (brokenVault) Describe() string { return "broken" }
func (brokenVault) Save(context.Context, vault.Entry) error {
	return errors.New("disk full")
}
func (brokenVault) Load(context.Context, string, string) (vault.Entry, error) {
	return vault.Entry{}, vault.ErrNotFound
}
func (brokenVault) List(context.Context, string) ([]string, error) { return nil, errors.New("locked") }

type saveFailsVault struct{ brokenVault }

func (saveFailsVault) List(context.Context, string) ([]string, error) { return nil, nil }

func TestPrepareReportsWhichVaultsHoldExistingCertificates(t *testing.T) {
	ctx := context.Background()
	store := local.New(t.TempDir())
	if err := store.Save(ctx, vault.Entry{Team: "TEAM123456", CertificateID: "OURS", P12: []byte("x"), Password: "y"}); err != nil {
		t.Fatal(err)
	}
	portal := &fakePortal{existing: []signing.Certificate{
		{ID: "THEIRS", Type: signing.CertificateTypeIOSDistribution, ExpiresAt: time.Now().AddDate(0, 6, 0)},
		{ID: "OURS", Type: signing.CertificateTypeDistribution, ExpiresAt: time.Now().AddDate(0, 1, 0)},
		{ID: "DEV", Type: "DEVELOPMENT", ExpiresAt: time.Now().AddDate(1, 0, 0)},
	}}

	plan, err := Prepare(ctx, portal, []vault.Vault{store}, "TEAM123456")

	if err != nil || len(plan.Existing) != 2 || plan.Existing[0].Certificate.ID != "OURS" || len(plan.Existing[0].HeldBy) != 1 || len(plan.Existing[1].HeldBy) != 0 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if _, err := Prepare(ctx, portal, []vault.Vault{store, brokenVault{}}, "TEAM123456"); err == nil || !strings.Contains(err.Error(), "broken: locked") {
		t.Fatalf("Prepare with an unreadable vault = %v", err)
	}
	if _, err := Prepare(ctx, portal, nil, "TEAM123456"); err == nil {
		t.Fatal("Prepare without vaults succeeded")
	}
}

func TestCreateSavesAUsableIdentityToEveryVault(t *testing.T) {
	ctx := context.Background()
	first, second := local.New(t.TempDir()), local.New(t.TempDir())
	portal := &fakePortal{}

	recoveryRoot := t.TempDir()
	created, err := Create(ctx, portal, []vault.Vault{first, second}, local.NewRecovery(recoveryRoot), "TEAM123456")

	if err != nil || len(created.SavedTo) != 2 || len(created.Failures) != 0 || created.Recovery != "" {
		t.Fatalf("created = %+v, %v", created, err)
	}
	if keys, _ := filepath.Glob(filepath.Join(recoveryRoot, "keys", "*")); len(keys) != 0 {
		t.Fatalf("the pending key was kept after the identity was saved: %v", keys)
	}
	entry, err := second.Load(ctx, "TEAM123456", created.Certificate.ID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := identity.Open(entry.P12, entry.Password)
	if err != nil || opened.Fingerprint() != created.Fingerprint {
		t.Fatalf("stored identity = %v, %v", opened.Fingerprint(), err)
	}
}

func TestCreateFallsBackToRecoveryWhenNoVaultSaves(t *testing.T) {
	ctx := context.Background()
	recoveryRoot := filepath.Join(t.TempDir(), "recovery")

	created, err := Create(ctx, &fakePortal{}, []vault.Vault{saveFailsVault{}}, local.NewRecovery(recoveryRoot), "TEAM123456")

	if err != nil || created.Recovery != filepath.Join(recoveryRoot, "identities", created.Certificate.ID) || len(created.Failures) != 1 {
		t.Fatalf("created = %+v, %v", created, err)
	}
	if ids, _ := local.New(filepath.Join(recoveryRoot, "identities")).List(ctx, "TEAM123456"); !slices.Equal(ids, []string{created.Certificate.ID}) {
		t.Fatalf("recovery holds %v", ids)
	}
}

// failingPortal fails the create request the way a timeout would: Apple may have created it.
type failingPortal struct{ fakePortal }

func (*failingPortal) CreateCertificate(context.Context, []byte) (signing.Certificate, []byte, error) {
	return signing.Certificate{}, nil, errors.New("context deadline exceeded")
}

func TestAFailedRequestKeepsTheKey(t *testing.T) {
	recoveryRoot := t.TempDir()

	_, err := Create(context.Background(), &failingPortal{}, []vault.Vault{local.New(t.TempDir())}, local.NewRecovery(recoveryRoot), "TEAM123456")

	keys, _ := filepath.Glob(filepath.Join(recoveryRoot, "keys", "TEAM123456-*.key.pem"))
	if err == nil || len(keys) != 1 || !strings.Contains(err.Error(), "Apple may still have created the certificate") || !strings.Contains(err.Error(), keys[0]) {
		t.Fatalf("err = %v, keys = %v", err, keys)
	}
	data, _ := os.ReadFile(keys[0])
	if block, _ := pem.Decode(data); block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("the kept key is not a PEM private key")
	}
	if info, _ := os.Stat(keys[0]); info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v", info.Mode())
	}
}
