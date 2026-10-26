package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSetEncryptsForTheRepositoryKey(t *testing.T) {
	public, private, _ := box.GenerateKey(rand.Reader)
	var stored map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/app/environments/Production/secrets/public-key":
			fmt.Fprintf(w, `{"key_id": "KEY1", "key": %q}`, base64.StdEncoding.EncodeToString(public[:]))
		case r.Method == http.MethodPut && r.URL.Path == "/repos/owner/app/environments/Production/secrets/CERTIFICATE_BASE64":
			json.NewDecoder(r.Body).Decode(&stored)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	t.Cleanup(server.Close)
	store := New(server.URL, "owner/app", "Production", func() (string, error) { return "gh-token", nil }, server.Client())

	if err := store.Set(context.Background(), "CERTIFICATE_BASE64", []byte("secret value")); err != nil {
		t.Fatal(err)
	}

	if stored["key_id"] != "KEY1" || strings.Contains(stored["encrypted_value"], "secret value") {
		t.Fatalf("stored = %v", stored)
	}
	sealed, _ := base64.StdEncoding.DecodeString(stored["encrypted_value"])
	opened, ok := box.OpenAnonymous(nil, sealed, public, private)
	if !ok || string(opened) != "secret value" {
		t.Fatalf("opened = %q, %v", opened, ok)
	}
}

func TestUpdatedPagesThroughSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/app/actions/secrets" {
			t.Errorf("unexpected %s", r.URL)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			fmt.Fprint(w, `{"total_count": 2, "secrets": [{"name": "A", "updated_at": "2026-01-02T03:04:05Z"}]}`)
		case "2":
			fmt.Fprint(w, `{"total_count": 2, "secrets": [{"name": "B", "updated_at": "2026-02-02T03:04:05Z"}]}`)
		}
	}))
	t.Cleanup(server.Close)
	store := New(server.URL, "owner/app", "", func() (string, error) { return "t", nil }, server.Client())

	updated, err := store.Updated(context.Background())

	if err != nil || len(updated) != 2 || updated["B"].Month() != 2 {
		t.Fatalf("updated = %v, %v", updated, err)
	}
}

func TestErrorsNameTheStoreAndCarryGitHubsMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message": "Resource not accessible by integration"}`)
	}))
	t.Cleanup(server.Close)
	store := New(server.URL, "owner/app", "", func() (string, error) { return "t", nil }, server.Client())

	err := store.Set(context.Background(), "X", []byte("v"))

	if err == nil || err.Error() != "GitHub owner/app: GET /repos/owner/app/actions/secrets/public-key failed (403): Resource not accessible by integration" {
		t.Fatalf("err = %v", err)
	}
}
