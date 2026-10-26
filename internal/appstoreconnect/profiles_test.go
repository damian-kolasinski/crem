package appstoreconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/damian-kolasinski/crem/internal/appstoreconnect/jsonapi"
	"github.com/damian-kolasinski/crem/internal/signing"
)

func TestCreateProfileResolvesTheBundleIDAndSendsRelationships(t *testing.T) {
	var body struct {
		Data struct {
			Attributes    map[string]string `json:"attributes"`
			Relationships map[string]struct {
				Data json.RawMessage `json:"data"`
			} `json:"relationships"`
		} `json:"data"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/bundleIds":
			if r.URL.Query().Get("filter[identifier]") != "com.example.demo" {
				t.Errorf("query = %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"data": [
				{"type": "bundleIds", "id": "LONGER", "attributes": {"identifier": "com.example.demo.share"}},
				{"type": "bundleIds", "id": "EXACT", "attributes": {"identifier": "com.example.demo"}}
			]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/profiles":
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"data": {"type": "profiles", "id": "NEWPROFILE", "attributes": {
				"name": "AdHoc com.example.demo", "profileType": "IOS_APP_ADHOC", "profileState": "ACTIVE", "uuid": "U",
				"createdDate": "2026-10-26T12:00:00.000+00:00", "expirationDate": "2027-10-26T12:00:00.000+00:00"}}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	t.Cleanup(server.Close)
	api, _ := jsonapi.New(server.URL, staticToken{}, server.Client())

	created, err := New(api).CreateProfile(context.Background(), signing.NewProfile{
		Name: "AdHoc com.example.demo", Type: signing.ProfileTypeIOSAdHoc, BundleID: "com.example.demo", CertificateID: "CERT", DeviceIDs: []string{"D1", "D2"},
	})

	if err != nil || created.ID != "NEWPROFILE" || created.BundleID != "com.example.demo" || !created.UsesCertificate("CERT") {
		t.Fatalf("created = %+v, %v", created, err)
	}
	if body.Data.Attributes["profileType"] != "IOS_APP_ADHOC" || body.Data.Attributes["name"] != "AdHoc com.example.demo" {
		t.Fatalf("attributes = %v", body.Data.Attributes)
	}
	for relationship, want := range map[string]string{
		"bundleId":     `{"type":"bundleIds","id":"EXACT"}`,
		"certificates": `[{"type":"certificates","id":"CERT"}]`,
		"devices":      `[{"type":"devices","id":"D1"},{"type":"devices","id":"D2"}]`,
	} {
		if got := string(body.Data.Relationships[relationship].Data); got != want {
			t.Errorf("%s = %s, want %s", relationship, got, want)
		}
	}
}

func TestDeleteProfile(t *testing.T) {
	var deleted string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = r.URL.Path
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	api, _ := jsonapi.New(server.URL, staticToken{}, server.Client())

	if err := New(api).DeleteProfile(context.Background(), "P1"); err != nil || deleted != "/v1/profiles/P1" {
		t.Fatalf("deleted = %q, %v", deleted, err)
	}
}

func TestCreateProfileRefusesUnregisteredBundleIDs(t *testing.T) {
	client := newTestClient(t, map[string]string{"/v1/bundleIds": `{"data": [{"type": "bundleIds", "id": "X", "attributes": {"identifier": "com.example.demo.share"}}]}`})

	if _, err := client.CreateProfile(context.Background(), signing.NewProfile{BundleID: "com.example.demo"}); err == nil {
		t.Fatal("created a profile for an unregistered bundle ID")
	}
}
