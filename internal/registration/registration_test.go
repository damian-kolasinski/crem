package registration

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/damian-kolasinski/crem/internal/signing"
)

type team struct {
	capabilities map[string][]signing.Capability
	names        map[string]string
	refuse       string
}

func (t *team) BundleIDs(context.Context) ([]signing.BundleID, error) {
	var ids []signing.BundleID
	for identifier := range t.capabilities {
		ids = append(ids, signing.BundleID{Identifier: identifier})
	}
	return ids, nil
}
func (t *team) BundleIDCapabilities(_ context.Context, identifier string) ([]signing.Capability, error) {
	return t.capabilities[identifier], nil
}
func (t *team) RegisterBundleID(_ context.Context, identifier, name string) error {
	// App Store Connect enables some capabilities on every new App ID.
	t.capabilities[identifier] = []signing.Capability{{Type: "IN_APP_PURCHASE"}}
	t.names[identifier] = name
	return nil
}
func (t *team) EnableCapability(_ context.Context, identifier string, capability signing.Capability) error {
	if capability.Type == t.refuse {
		return errors.New("needs a container")
	}
	t.capabilities[identifier] = append(t.capabilities[identifier], capability)
	return nil
}

func manifest() signing.Manifest {
	return signing.Manifest{
		Team: "TEAM123456",
		Targets: []signing.Target{
			{App: "Demo App", Environment: "Production", BundleID: "com.example.demo"},
			{App: "Demo App", Environment: "Production", Extension: "share", BundleID: "com.example.demo.share"},
			{App: "Demo App", Environment: "Staging", BundleID: "com.example.demo.staging"},
			{App: "Demo App", Environment: "Staging", Extension: "share", BundleID: "com.example.demo.staging.share"},
		},
	}
}

func existingTeam() *team {
	return &team{
		capabilities: map[string][]signing.Capability{
			"com.example.demo":       {{Type: "IN_APP_PURCHASE"}, {Type: "PUSH_NOTIFICATIONS"}, {Type: "APP_GROUPS"}},
			"com.example.demo.share": {{Type: "APP_GROUPS"}},
			"com.example.other":      {{Type: "ASSOCIATED_DOMAINS"}},
		},
		names: map[string]string{},
	}
}

func TestRegistersMissingBundleIDsWithTheirSiblingsCapabilities(t *testing.T) {
	ctx := context.Background()
	portal := existingTeam()
	portal.refuse = "APP_GROUPS"

	plan, err := Prepare(ctx, portal, manifest(), Request{})
	if err != nil || plan.Registered != 2 || len(plan.Registrations) != 2 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if plan.Registrations[0].CapabilitiesFrom != "com.example.demo" || plan.Registrations[1].CapabilitiesFrom != "com.example.demo.share" {
		t.Fatalf("sources = %s, %s", plan.Registrations[0].CapabilitiesFrom, plan.Registrations[1].CapabilitiesFrom)
	}

	done, err := Execute(ctx, portal, plan)
	if err != nil || len(done) != 2 {
		t.Fatalf("done = %+v, %v", done, err)
	}
	var types []string
	for _, capability := range portal.capabilities["com.example.demo.staging"] {
		types = append(types, capability.Type)
	}
	if !slices.Equal(types, []string{"IN_APP_PURCHASE", "PUSH_NOTIFICATIONS"}) || done[0].Failed["APP_GROUPS"] == nil {
		t.Fatalf("enabled = %v, failed = %v", types, done[0].Failed)
	}
	if portal.names["com.example.demo.staging.share"] != "Demo App Staging share" {
		t.Fatalf("name = %q", portal.names["com.example.demo.staging.share"])
	}
	if again, _ := Prepare(ctx, portal, manifest(), Request{}); len(again.Registrations) != 0 || again.Registered != 4 {
		t.Fatalf("second plan = %+v", again)
	}
}

func TestRequestNarrowsAndOverridesTheSource(t *testing.T) {
	plan, err := Prepare(context.Background(), existingTeam(), manifest(), Request{BundleIDs: []string{"com.example.demo.staging"}, CapabilitiesFrom: "com.example.other"})
	if err != nil || len(plan.Registrations) != 1 || plan.Registrations[0].Capabilities[0].Type != "ASSOCIATED_DOMAINS" {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	for request, want := range map[*Request]string{
		{BundleIDs: []string{"com.example.unknown"}}: "is not in crem.yaml",
		{CapabilitiesFrom: "com.example.missing"}:    "is not registered",
	} {
		if _, err := Prepare(context.Background(), existingTeam(), manifest(), *request); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestARequestedBundleIDIsCompletedWithMissingCapabilities(t *testing.T) {
	ctx := context.Background()
	portal := existingTeam()
	portal.capabilities["com.example.demo.staging"] = []signing.Capability{{Type: "IN_APP_PURCHASE"}}

	untouched, _ := Prepare(ctx, portal, manifest(), Request{})
	plan, err := Prepare(ctx, portal, manifest(), Request{BundleIDs: []string{"com.example.demo.staging"}})

	if len(untouched.Registrations) != 1 || untouched.Registrations[0].Target.BundleID != "com.example.demo.staging.share" {
		t.Fatalf("without a request, registered bundle IDs are left alone: %+v", untouched.Registrations)
	}
	if err != nil || len(plan.Registrations) != 1 || !plan.Registrations[0].AlreadyRegistered || len(plan.Registrations[0].Capabilities) != 2 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if _, err := Execute(ctx, portal, plan); err != nil {
		t.Fatal(err)
	}
	if again, _ := Prepare(ctx, portal, manifest(), Request{BundleIDs: []string{"com.example.demo.staging"}}); len(again.Registrations) != 0 {
		t.Fatalf("second plan = %+v", again.Registrations)
	}
}
