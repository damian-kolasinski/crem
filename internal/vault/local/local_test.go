package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/vault"
)

func entry(id string) vault.Entry {
	return vault.Entry{Team: "TEAM123456", CertificateID: id, SerialNumber: "AB12", ExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), P12: []byte("p12"), Password: "secret"}
}

func TestSaveLoadAndList(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)

	if ids, err := store.List(ctx, "TEAM123456"); !errors.Is(err, vault.ErrNotSetUp) || len(ids) != 0 {
		t.Fatalf("List on a missing root = %v, %v", ids, err)
	}
	for _, id := range []string{"CERT2", "CERT1"} {
		if err := store.Save(ctx, entry(id)); err != nil {
			t.Fatal(err)
		}
	}
	other := entry("CERT3")
	other.Team = "OTHER12345"
	if err := store.Save(ctx, other); err != nil {
		t.Fatal(err)
	}

	ids, err := store.List(ctx, "TEAM123456")
	if err != nil || !slices.Equal(ids, []string{"CERT1", "CERT2"}) {
		t.Fatalf("List = %v, %v", ids, err)
	}
	loaded, err := store.Load(ctx, "TEAM123456", "CERT1")
	if err != nil || string(loaded.P12) != "p12" || loaded.Password != "secret" || !loaded.ExpiresAt.Equal(entry("CERT1").ExpiresAt) {
		t.Fatalf("Load = %+v, %v", loaded, err)
	}
	if _, err := store.Load(ctx, "TEAM123456", "CERT3"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Load of another team's identity = %v", err)
	}
	if _, err := store.Load(ctx, "TEAM123456", "MISSING"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Load of a missing identity = %v", err)
	}
}

func TestSaveNeverReplacesAndKeepsFilesPrivate(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := New(root)

	if err := store.Save(ctx, entry("CERT1")); err != nil {
		t.Fatal(err)
	}
	replacement := entry("CERT1")
	replacement.Password = "other"
	if err := store.Save(ctx, replacement); !errors.Is(err, vault.ErrExists) {
		t.Fatalf("second Save = %v", err)
	}

	for _, name := range []string{p12File, passwordFile, metadataFile} {
		info, err := os.Stat(filepath.Join(root, "CERT1", name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, %v", name, info.Mode(), err)
		}
	}
	if info, _ := os.Stat(filepath.Join(root, "CERT1")); info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v", info.Mode())
	}
	if loaded, _ := store.Load(ctx, "TEAM123456", "CERT1"); loaded.Password != "secret" {
		t.Fatal("the identity was replaced")
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, ".saving-*"))
	if len(leftovers) != 0 {
		t.Fatalf("staging directories left behind: %v", leftovers)
	}
}

func TestCertificateIDsCannotEscapeTheRoot(t *testing.T) {
	store := New(t.TempDir())
	if err := store.Save(context.Background(), entry("../escape")); err == nil {
		t.Fatal("saved outside the root")
	}
}
