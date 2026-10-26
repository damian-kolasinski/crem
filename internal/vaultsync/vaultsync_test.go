package vaultsync

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/identity"
	"github.com/damian-kolasinski/crem/internal/vault"
	"github.com/damian-kolasinski/crem/internal/vault/local"
)

func entry(t *testing.T, id string) vault.Entry {
	t.Helper()
	key, _ := identity.NewKey()
	authority, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: id}, NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, authority)
	issued, _ := identity.New(der, key)
	p12, _ := issued.P12("password")
	return vault.Entry{Team: "TEAM123456", CertificateID: id, P12: p12, Password: "password"}
}

func TestSyncCopiesEveryIdentityToEveryVault(t *testing.T) {
	ctx := context.Background()
	first := local.New(t.TempDir())
	second := local.New(t.TempDir())
	notSetUp := local.New(filepath.Join(t.TempDir(), "new"))
	if err := first.Save(ctx, entry(t, "CERT1")); err != nil {
		t.Fatal(err)
	}
	if err := second.Save(ctx, entry(t, "CERT2")); err != nil {
		t.Fatal(err)
	}
	vaults := []vault.Vault{first, second, notSetUp}

	plan, err := Prepare(ctx, vaults, "TEAM123456")
	if err != nil || len(plan.Copies) != 2 || len(plan.Copies[0].To) != 2 || plan.Copies[0].From[0] != first {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	copied, err := Execute(ctx, plan, "TEAM123456")
	if err != nil || len(copied) != 4 {
		t.Fatalf("copied = %v, %v", copied, err)
	}

	for _, store := range vaults {
		if ids, _ := store.List(ctx, "TEAM123456"); !slices.Equal(ids, []string{"CERT1", "CERT2"}) {
			t.Fatalf("%s holds %v", store.Describe(), ids)
		}
	}
	if again, _ := Prepare(ctx, vaults, "TEAM123456"); len(again.Copies) != 0 || again.InSync != 2 {
		t.Fatalf("second plan = %+v", again)
	}
}

func TestSyncFallsBackToAUsableCopyAndReportsAlreadyHeld(t *testing.T) {
	ctx := context.Background()
	broken, good, target := local.New(t.TempDir()), local.New(t.TempDir()), local.New(t.TempDir())
	usable := entry(t, "CERT1")
	unusable := usable
	unusable.Password = "wrong"
	broken.Save(ctx, unusable)
	good.Save(ctx, usable)
	plan, _ := Prepare(ctx, []vault.Vault{broken, good, target}, "TEAM123456")
	// The target gains the identity between planning and copying.
	target.Save(ctx, usable)

	results, err := Execute(ctx, plan, "TEAM123456")

	if err != nil || len(results) != 1 || !results[0].AlreadyHeld {
		t.Fatalf("results = %+v, %v", results, err)
	}
}

func TestSyncRefusesAnUnusableIdentity(t *testing.T) {
	ctx := context.Background()
	first, second := local.New(t.TempDir()), local.New(t.TempDir())
	broken := entry(t, "CERT1")
	broken.Password = "wrong"
	if err := first.Save(ctx, broken); err != nil {
		t.Fatal(err)
	}
	plan, _ := Prepare(ctx, []vault.Vault{first, second}, "TEAM123456")

	if _, err := Execute(ctx, plan, "TEAM123456"); err == nil {
		t.Fatal("copied an identity whose .p12 does not open")
	}
	if ids, _ := second.List(ctx, "TEAM123456"); len(ids) != 0 {
		t.Fatalf("second holds %v", ids)
	}
}
