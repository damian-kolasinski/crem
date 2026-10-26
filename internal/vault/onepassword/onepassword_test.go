package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/vault"
)

// fakeOp is an in-memory 1Password that understands the op commands the adapter sends.
type fakeOp struct {
	items []item
	calls [][]string
}

func (f *fakeOp) Run(_ context.Context, stdin []byte, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if flag(args, "--vault") != "Mobile" || flag(args, "--format") != "json" {
		return nil, fmt.Errorf("unexpected flags %v", args)
	}
	switch {
	case args[0] == "item" && args[1] == "create" && slices.Contains(args, "-"):
		var created item
		if err := json.Unmarshal(stdin, &created); err != nil {
			return nil, err
		}
		// Like op, add the flag's tags to any the template carries; the adapter must send each once.
		created.Tags = append(created.Tags, strings.Split(flag(args, "--tags"), ",")...)
		// Custom field IDs may not survive, so crem also finds fields by label.
		for index := range created.Fields {
			if created.Fields[index].ID != "password" && created.Fields[index].ID != "notesPlain" {
				created.Fields[index].ID = fmt.Sprintf("generated%d", index)
			}
		}
		created.ID = fmt.Sprintf("item%d", len(f.items)+1)
		f.items = append(f.items, created)
		return json.Marshal(created)
	case args[0] == "item" && args[1] == "list":
		tag := flag(args, "--tags")
		var listed []item
		for _, stored := range f.items {
			// op matches nested tags too, and never returns field values from list.
			if slices.ContainsFunc(stored.Tags, func(candidate string) bool { return candidate == tag || strings.HasPrefix(candidate, tag+"/") }) {
				listed = append(listed, item{ID: stored.ID, Title: stored.Title, Tags: stored.Tags})
			}
		}
		return json.Marshal(listed)
	case args[0] == "item" && args[1] == "get" && slices.Contains(args, "--reveal"):
		for _, stored := range f.items {
			if stored.ID == args[2] {
				return json.Marshal(stored)
			}
		}
		return nil, errors.New("not found")
	}
	return nil, fmt.Errorf("unexpected op %v", args)
}

func flag(args []string, name string) string {
	index := slices.Index(args, name)
	if index < 0 || index+1 >= len(args) {
		return ""
	}
	return args[index+1]
}

func entry(team, id string) vault.Entry {
	return vault.Entry{Team: team, CertificateID: id, SerialNumber: "AB12", ExpiresAt: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), P12: []byte{0, 1, 2, 255}, Password: "s3cret"}
}

func TestSaveLoadAndList(t *testing.T) {
	ctx := context.Background()
	op := &fakeOp{}
	store := New("Mobile", "", op)

	for _, saved := range []vault.Entry{entry("TEAM123456", "CERT2"), entry("TEAM123456", "CERT1"), entry("OTHER12345", "CERT3")} {
		if err := store.Save(ctx, saved); err != nil {
			t.Fatal(err)
		}
	}

	ids, err := store.List(ctx, "TEAM123456")
	if err != nil || !slices.Equal(ids, []string{"CERT1", "CERT2"}) {
		t.Fatalf("List = %v, %v", ids, err)
	}
	loaded, err := store.Load(ctx, "TEAM123456", "CERT1")
	want := entry("TEAM123456", "CERT1")
	if err != nil || string(loaded.P12) != string(want.P12) || loaded.Password != want.Password || !loaded.ExpiresAt.Equal(want.ExpiresAt) || loaded.SerialNumber != "AB12" {
		t.Fatalf("Load = %+v, %v", loaded, err)
	}
	if _, err := store.Load(ctx, "TEAM123456", "CERT3"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Load of another team's identity = %v", err)
	}
}

func TestSecretsNeverAppearInArguments(t *testing.T) {
	op := &fakeOp{}
	store := New("Mobile", "work", op)

	if err := store.Save(context.Background(), entry("TEAM123456", "CERT1")); err != nil {
		t.Fatal(err)
	}

	for _, call := range op.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "s3cret") || strings.Contains(joined, "AAEC/w==") {
			t.Fatalf("secret in arguments: %v", call)
		}
		if flag(call, "--account") != "work" {
			t.Fatalf("missing account: %v", call)
		}
	}
}

func TestSavedItemsCarryEachTagOnce(t *testing.T) {
	op := &fakeOp{}
	if err := New("Mobile", "", op).Save(context.Background(), entry("TEAM123456", "CERT1")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"crem", "crem/TEAM123456", "crem/TEAM123456/CERT1"}; !slices.Equal(op.items[0].Tags, want) {
		t.Fatalf("tags = %v, want %v", op.items[0].Tags, want)
	}
}

func TestSaveNeverReplaces(t *testing.T) {
	store := New("Mobile", "", &fakeOp{})
	if err := store.Save(context.Background(), entry("TEAM123456", "CERT1")); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), entry("TEAM123456", "CERT1")); !errors.Is(err, vault.ErrExists) {
		t.Fatalf("second Save = %v", err)
	}
}
