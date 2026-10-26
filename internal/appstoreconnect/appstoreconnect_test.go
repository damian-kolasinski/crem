package appstoreconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/damian-kolasinski/crem/internal/appstoreconnect/jsonapi"
	"github.com/damian-kolasinski/crem/internal/signing"
)

type staticToken struct{}

func (staticToken) Token() (string, error) { return "token", nil }

func newTestClient(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	api, err := jsonapi.New(server.URL, staticToken{}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return New(api)
}

func TestProfilesResolveBundleIDsAndCertificates(t *testing.T) {
	client := newTestClient(t, map[string]string{"/v1/profiles": `{
		"data": [{
			"type": "profiles", "id": "P1",
			"attributes": {"name": "com.example.demo", "profileType": "IOS_APP_STORE", "profileState": "ACTIVE", "uuid": "U1",
				"createdDate": "2026-10-24T13:13:17.000+00:00", "expirationDate": "2027-10-02T07:31:31.000+00:00"},
			"relationships": {
				"bundleId": {"data": {"type": "bundleIds", "id": "B1"}},
				"certificates": {"data": [{"type": "certificates", "id": "C1"}]}
			}
		}],
		"included": [{"type": "bundleIds", "id": "B1", "attributes": {"identifier": "com.example.demo"}}]
	}`})

	profiles, err := client.Profiles(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	want := signing.Profile{
		ID: "P1", Name: "com.example.demo", Type: signing.ProfileTypeIOSAppStore, State: signing.ProfileStateActive, UUID: "U1",
		BundleID: "com.example.demo", CertificateIDs: []string{"C1"},
		CreatedAt: time.Date(2026, 10, 24, 13, 13, 17, 0, time.UTC), ExpiresAt: time.Date(2027, 10, 2, 7, 31, 31, 0, time.UTC),
	}
	got := profiles[0]
	if got.ID != want.ID || got.BundleID != want.BundleID || !got.ExpiresAt.Equal(want.ExpiresAt) || !got.CreatedAt.Equal(want.CreatedAt) ||
		len(got.CertificateIDs) != 1 || got.CertificateIDs[0] != "C1" || got.Type != want.Type || got.State != want.State {
		t.Fatalf("profile = %+v", got)
	}
}

func TestAdHocDevicesKeepOnlyAdHocClasses(t *testing.T) {
	client := newTestClient(t, map[string]string{"/v1/devices": `{"data": [
		{"type": "devices", "id": "D1", "attributes": {"name": "Phone", "udid": "1", "deviceClass": "IPHONE"}},
		{"type": "devices", "id": "D2", "attributes": {"name": "Watch", "udid": "2", "deviceClass": "APPLE_WATCH"}},
		{"type": "devices", "id": "D3", "attributes": {"name": "Tablet", "udid": "3", "deviceClass": "IPAD"}}
	]}`})

	devices, err := client.AdHocDevices(context.Background())

	if err != nil || len(devices) != 2 || devices[0].ID != "D1" || devices[1].ID != "D3" {
		t.Fatalf("devices = %v, %v", devices, err)
	}
}

func TestCreateCertificateSendsTheCSRAndReturnsTheDER(t *testing.T) {
	var body struct {
		Data struct {
			Type       string            `json:"type"`
			Attributes map[string]string `json:"attributes"`
		} `json:"data"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/certificates" {
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"data": {"type": "certificates", "id": "NEW", "attributes": {
			"name": "Apple Distribution: Example", "certificateType": "DISTRIBUTION", "serialNumber": "AB12",
			"expirationDate": "2027-10-26T12:00:00.000+00:00", "certificateContent": "AAEC"}}}`)
	}))
	t.Cleanup(server.Close)
	api, _ := jsonapi.New(server.URL, staticToken{}, server.Client())

	created, der, err := New(api).CreateCertificate(context.Background(), []byte("-----BEGIN CERTIFICATE REQUEST-----"))

	if err != nil || created.ID != "NEW" || created.SerialNumber != "AB12" || string(der) != "\x00\x01\x02" {
		t.Fatalf("created = %+v, der = %v, err = %v", created, der, err)
	}
	if attributes := body.Data.Attributes; body.Data.Type != "certificates" || attributes["certificateType"] != "DISTRIBUTION" || attributes["csrContent"] != "-----BEGIN CERTIFICATE REQUEST-----" {
		t.Fatalf("attributes = %v", attributes)
	}
}

func TestUnreadableResourcesAreErrors(t *testing.T) {
	client := newTestClient(t, map[string]string{"/v1/certificates": `{"data": [
		{"type": "certificates", "id": "C1", "attributes": {"certificateType": "DISTRIBUTION", "expirationDate": "soon"}}
	]}`})

	if _, err := client.Certificates(context.Background()); err == nil {
		t.Fatal("accepted an unreadable expiration date")
	}
}
