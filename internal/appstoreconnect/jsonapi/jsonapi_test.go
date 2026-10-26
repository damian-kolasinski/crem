package jsonapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type staticToken string

func (t staticToken) Token() (string, error) { return string(t), nil }

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(server.URL, staticToken("token"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.sleep = func(context.Context, time.Duration) error { return nil }
	return client, server
}

func TestGetAllFollowsPaginationAndKeepsIncluded(t *testing.T) {
	var server *httptest.Server
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			if r.URL.Query().Get("limit") != "200" {
				t.Errorf("query = %s", r.URL.RawQuery)
			}
			fmt.Fprintf(w, `{"data":[{"type":"profiles","id":"1"}],"included":[{"type":"bundleIds","id":"B"}],"links":{"next":"%s/v1/profiles?cursor=2"}}`, server.URL)
		case "2":
			fmt.Fprint(w, `{"data":[{"type":"profiles","id":"2","relationships":{"certificates":{"data":[{"type":"certificates","id":"C1"},{"type":"certificates","id":"C2"}]}}}]}`)
		}
	})

	data, included, err := client.GetAll(context.Background(), "/v1/profiles", url.Values{"limit": {"200"}})

	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2 || data[1].ID != "2" || len(included) != 1 {
		t.Fatalf("data = %v, included = %v", data, included)
	}
	if ids := data[1].Relationships["certificates"].IDs(); len(ids) != 2 || ids[1] != "C2" {
		t.Fatalf("relationship ids = %v", ids)
	}
}

func TestGetAllRejectsForeignPaginationHosts(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[],"links":{"next":"https://attacker.example/v1/profiles?cursor=2"}}`)
	})

	if _, _, err := client.GetAll(context.Background(), "/v1/profiles", nil); err == nil {
		t.Fatal("followed a foreign pagination link")
	}
}

func TestErrorsCarryTheAPIErrorDetail(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"errors":[{"code":"NOT_FOUND","title":"Not found","detail":"There is no resource with id 'X'."}]}`)
	})

	_, _, err := client.GetAll(context.Background(), "/v1/profiles/X/devices", nil)

	var apiError *Error
	if !errors.As(err, &apiError) || apiError.Code != "NOT_FOUND" || apiError.Status != http.StatusNotFound {
		t.Fatalf("err = %v", err)
	}
	if want := "App Store Connect GET /v1/profiles/X/devices failed (404 NOT_FOUND): There is no resource with id 'X'."; err.Error() != want {
		t.Fatalf("message = %q", err.Error())
	}
}

func TestReadsAreRetriedButWritesAreNot(t *testing.T) {
	calls := map[string]int{}
	var delays []time.Duration
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls[r.Method]++
		if r.Method == http.MethodGet && calls[r.Method] == 3 {
			fmt.Fprint(w, `{"data":[{"type":"certificates","id":"C"}]}`)
			return
		}
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	client.sleep = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}

	data, _, err := client.GetAll(context.Background(), "/v1/certificates", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 || calls[http.MethodGet] != 3 {
		t.Fatalf("data = %v after %d calls", data, calls[http.MethodGet])
	}
	if len(delays) != 2 || delays[0] != maxRetryDelay {
		t.Fatalf("delays = %v", delays)
	}

	if _, err := client.Post(context.Background(), "/v1/certificates", map[string]string{}); err == nil || calls[http.MethodPost] != 1 {
		t.Fatalf("post err = %v after %d calls", err, calls[http.MethodPost])
	}
}
