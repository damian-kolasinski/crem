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

func TestCapabilitiesKeepOnlyEnabledOptions(t *testing.T) {
	client := newTestClient(t, map[string]string{
		"/v1/bundleIds": `{"data": [{"type": "bundleIds", "id": "B1", "attributes": {"identifier": "com.example.demo"}}]}`,
		"/v1/bundleIds/B1/bundleIdCapabilities": `{"data": [
			{"type": "bundleIdCapabilities", "id": "C1", "attributes": {"capabilityType": "PUSH_NOTIFICATIONS"}},
			{"type": "bundleIdCapabilities", "id": "C2", "attributes": {"capabilityType": "DATA_PROTECTION", "settings": [
				{"key": "DATA_PROTECTION_PERMISSION_LEVEL", "options": [{"key": "COMPLETE_PROTECTION", "enabled": true}, {"key": "PROTECTED_UNLESS_OPEN", "enabled": false}]}
			]}}
		]}`,
	})

	capabilities, err := client.BundleIDCapabilities(context.Background(), "com.example.demo")

	if err != nil || len(capabilities) != 2 || capabilities[1].Settings[0].Options[0] != "COMPLETE_PROTECTION" || len(capabilities[1].Settings[0].Options) != 1 {
		t.Fatalf("capabilities = %+v, %v", capabilities, err)
	}
}

func TestRegisterAndEnableSendTheExpectedRequests(t *testing.T) {
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/bundleIds":
			fmt.Fprint(w, `{"data": [{"type": "bundleIds", "id": "B9", "attributes": {"identifier": "com.example.new"}}]}`)
		case r.Method == http.MethodPost:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			bodies = append(bodies, body)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"data": {"type": "x", "id": "y"}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	t.Cleanup(server.Close)
	api, _ := jsonapi.New(server.URL, staticToken{}, server.Client())
	client := New(api)

	if err := client.RegisterBundleID(context.Background(), "com.example.new", "Demo Staging"); err != nil {
		t.Fatal(err)
	}
	if err := client.EnableCapability(context.Background(), "com.example.new", signing.Capability{Type: "APPLE_ID_AUTH"}); err != nil {
		t.Fatal(err)
	}

	encoded, _ := json.Marshal(bodies)
	want := `[{"data":{"attributes":{"identifier":"com.example.new","name":"Demo Staging","platform":"IOS"},"type":"bundleIds"}},` +
		`{"data":{"attributes":{"capabilityType":"APPLE_ID_AUTH","settings":[{"key":"APPLE_ID_AUTH_APP_CONSENT","options":[{"enabled":true,"key":"PRIMARY_APP_CONSENT"}]}]},"relationships":{"bundleId":{"data":{"id":"B9","type":"bundleIds"}}},"type":"bundleIdCapabilities"}}]`
	if string(encoded) != want {
		t.Fatalf("bodies = %s", encoded)
	}
}
