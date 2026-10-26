// Package registration registers the bundle IDs a project expects that the team lacks,
// copying capabilities from a bundle ID that already has them.
package registration

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/damian-kolasinski/crem/internal/signing"
)

// Portal reads and registers bundle IDs and their capabilities.
type Portal interface {
	BundleIDs(ctx context.Context) ([]signing.BundleID, error)
	BundleIDCapabilities(ctx context.Context, identifier string) ([]signing.Capability, error)
	RegisterBundleID(ctx context.Context, identifier, name string) error
	EnableCapability(ctx context.Context, identifier string, capability signing.Capability) error
}

// Registration is a bundle ID to register, or a registered one to complete.
type Registration struct {
	Target signing.Target
	Name   string
	// AlreadyRegistered is true for a requested bundle ID that exists but lacks capabilities of its source.
	AlreadyRegistered bool
	// CapabilitiesFrom is the registered bundle ID whose capabilities are copied; empty copies none.
	CapabilitiesFrom string
	// Capabilities are the source's capabilities the bundle ID lacks.
	Capabilities []signing.Capability
}

// Plan lists the bundle IDs to register.
type Plan struct {
	Registrations []Registration
	// Registered counts the expected bundle IDs the team already has.
	Registered int
}

// Request narrows and steers the plan.
type Request struct {
	// BundleIDs, when set, registers only these expected bundle IDs.
	BundleIDs []string
	// CapabilitiesFrom, when set, is the registered bundle ID to copy capabilities from for every registration.
	CapabilitiesFrom string
}

var nameUnsafe = regexp.MustCompile(`[^A-Za-z0-9 ]+`)

// Prepare finds the expected bundle IDs the team lacks and where each copies its capabilities from:
// the requested bundle ID, else the same app's same component in another environment. A bundle ID
// named in the request that is already registered is completed with the source's capabilities it
// lacks, which also finishes an earlier run that stopped partway; others are left as they are.
func Prepare(ctx context.Context, portal Portal, manifest signing.Manifest, request Request) (Plan, error) {
	registered, err := portal.BundleIDs(ctx)
	if err != nil {
		return Plan{}, err
	}
	isRegistered := func(identifier string) bool {
		return slices.ContainsFunc(registered, func(bundleID signing.BundleID) bool { return bundleID.Identifier == identifier })
	}
	for _, identifier := range request.BundleIDs {
		if _, managed := manifest.Target(identifier); !managed {
			return Plan{}, fmt.Errorf("%s is not in crem.yaml; add its app or extension first", identifier)
		}
	}
	if request.CapabilitiesFrom != "" && !isRegistered(request.CapabilitiesFrom) {
		return Plan{}, fmt.Errorf("%s is not registered, so its capabilities cannot be copied", request.CapabilitiesFrom)
	}

	var plan Plan
	for _, target := range manifest.Targets {
		if len(request.BundleIDs) > 0 && !slices.Contains(request.BundleIDs, target.BundleID) {
			continue
		}
		registered := isRegistered(target.BundleID)
		requested := slices.Contains(request.BundleIDs, target.BundleID)
		if registered && !requested {
			plan.Registered++
			continue
		}
		registration := Registration{Target: target, Name: name(target), AlreadyRegistered: registered, CapabilitiesFrom: request.CapabilitiesFrom}
		if registration.CapabilitiesFrom == "" {
			for _, sibling := range manifest.Targets {
				if sibling.App == target.App && sibling.Extension == target.Extension && sibling.Environment != target.Environment && isRegistered(sibling.BundleID) {
					registration.CapabilitiesFrom = sibling.BundleID
					break
				}
			}
		}
		if registration.CapabilitiesFrom != "" {
			if registration.Capabilities, err = portal.BundleIDCapabilities(ctx, registration.CapabilitiesFrom); err != nil {
				return Plan{}, err
			}
		}
		if registered {
			existing, err := portal.BundleIDCapabilities(ctx, target.BundleID)
			if err != nil {
				return Plan{}, err
			}
			var lacking []signing.Capability
			for _, capability := range registration.Capabilities {
				if !slices.ContainsFunc(existing, func(enabled signing.Capability) bool { return enabled.Type == capability.Type }) {
					lacking = append(lacking, capability)
				}
			}
			registration.Capabilities = lacking
			if len(registration.Capabilities) == 0 {
				plan.Registered++
				continue
			}
		}
		plan.Registrations = append(plan.Registrations, registration)
	}
	return plan, nil
}

// name is the App ID's description: App Store Connect accepts letters, digits, and spaces.
func name(target signing.Target) string {
	parts := []string{target.App, target.Environment}
	if target.Extension != "" {
		parts = append(parts, target.Extension)
	}
	return strings.Join(strings.Fields(nameUnsafe.ReplaceAllString(strings.Join(parts, " "), " ")), " ")
}

// Registered is a bundle ID Execute registered, with the capabilities that could not be enabled.
type Registered struct {
	Registration Registration
	Failed       map[string]error
}

// Execute registers each bundle ID and enables its copied capabilities, stopping when a
// registration fails. A capability that fails to enable is reported, not fatal: the bundle ID
// exists, and running again with --bundle-id completes it.
func Execute(ctx context.Context, portal Portal, plan Plan) ([]Registered, error) {
	var done []Registered
	for _, registration := range plan.Registrations {
		identifier := registration.Target.BundleID
		if !registration.AlreadyRegistered {
			if err := portal.RegisterBundleID(ctx, identifier, registration.Name); err != nil {
				return done, fmt.Errorf("registering %s: %w", identifier, err)
			}
		}
		result := Registered{Registration: registration, Failed: map[string]error{}}
		enabled, err := portal.BundleIDCapabilities(ctx, identifier)
		if err != nil {
			// The bundle ID exists, so report it before stopping.
			for _, capability := range registration.Capabilities {
				result.Failed[capability.Type] = err
			}
			return append(done, result), fmt.Errorf("reading the capabilities of %s, registered: %w", identifier, err)
		}
		for _, capability := range registration.Capabilities {
			if slices.ContainsFunc(enabled, func(existing signing.Capability) bool { return existing.Type == capability.Type }) {
				continue
			}
			if err := portal.EnableCapability(ctx, identifier, capability); err != nil {
				result.Failed[capability.Type] = err
			}
		}
		done = append(done, result)
	}
	return done, nil
}
