package signing

import (
	"fmt"
	"strings"
)

// ProfileKind is a kind of distribution profile a project expects for each bundle ID.
type ProfileKind int

const (
	AppStore ProfileKind = iota + 1
	AdHoc
)

// ParseProfileKind parses a kind's configuration name.
func ParseProfileKind(name string) (ProfileKind, error) {
	for _, kind := range []ProfileKind{AppStore, AdHoc} {
		if kind.String() == name {
			return kind, nil
		}
	}
	return 0, fmt.Errorf("unknown profile kind %q (expected app-store or ad-hoc)", name)
}

func (k ProfileKind) String() string {
	switch k {
	case AppStore:
		return "app-store"
	case AdHoc:
		return "ad-hoc"
	}
	return fmt.Sprintf("ProfileKind(%d)", int(k))
}

// ProfileType is the App Store Connect type of profiles of this kind.
func (k ProfileKind) ProfileType() ProfileType {
	if k == AdHoc {
		return ProfileTypeIOSAdHoc
	}
	return ProfileTypeIOSAppStore
}

// DeviceSelection decides which devices a new Ad Hoc profile includes.
type DeviceSelection int

const (
	// CarryOverDevices keeps the enabled devices of the profile being replaced.
	CarryOverDevices DeviceSelection = iota + 1
	// AllDevices includes every enabled device that Ad Hoc profiles accept.
	AllDevices
)

// ParseDeviceSelection parses a selection's configuration name.
func ParseDeviceSelection(name string) (DeviceSelection, error) {
	switch name {
	case "carry-over":
		return CarryOverDevices, nil
	case "all":
		return AllDevices, nil
	}
	return 0, fmt.Errorf("unknown device selection %q (expected carry-over or all)", name)
}

func (s DeviceSelection) String() string {
	if s == AllDevices {
		return "all"
	}
	return "carry-over"
}

// ProfileSpec describes the profile of one kind that every bundle ID gets.
type ProfileSpec struct {
	Kind    ProfileKind
	Name    Template
	Devices DeviceSelection
}

// Target is one bundle ID a project signs: an app or one of its extensions in one environment.
type Target struct {
	App         string
	Environment string
	// Extension is empty for the app itself.
	Extension string
	BundleID  string
	// Secret names the CI secret that carries the target's App Store profile; empty when CI reads none.
	Secret string
}

// Component names the target within its app: "app", or the extension's name.
func (t Target) Component() string {
	if t.Extension == "" {
		return "app"
	}
	return t.Extension
}

func (t Target) templateValues() map[string]string {
	return map[string]string{
		"app":         t.App,
		"environment": t.Environment,
		"extension":   t.Extension,
		"bundleId":    t.BundleID,
	}
}

// Scope selects bundle IDs by prefix: an ID is in scope when it equals or is
// nested under an included prefix and under no excluded one.
type Scope struct {
	Include []string
	Exclude []string
}

// Contains reports whether the bundle ID is in scope.
func (s Scope) Contains(bundleID string) bool {
	matches := func(prefix string) bool {
		return bundleID == prefix || strings.HasPrefix(bundleID, prefix+".")
	}
	return bundleID != "" && anyOf(s.Include, matches) && !anyOf(s.Exclude, matches)
}

func anyOf(values []string, predicate func(string) bool) bool {
	for _, value := range values {
		if predicate(value) {
			return true
		}
	}
	return false
}

// Manifest is the signing state a project expects.
type Manifest struct {
	Team     string
	Profiles []ProfileSpec
	Targets  []Target
	// Cleanup bounds what cleanup may delete or revoke.
	Cleanup Scope
}

// ExpectedProfile is the profile one spec requires for one target.
type ExpectedProfile struct {
	Target Target
	Spec   ProfileSpec
	Name   string
}

// ExpectedProfiles lists every profile the manifest requires, by target, then by spec.
func (m Manifest) ExpectedProfiles() []ExpectedProfile {
	expected := make([]ExpectedProfile, 0, len(m.Targets)*len(m.Profiles))
	for _, target := range m.Targets {
		for _, spec := range m.Profiles {
			expected = append(expected, ExpectedProfile{Target: target, Spec: spec, Name: spec.Name.Render(target.templateValues())})
		}
	}
	return expected
}

// Target returns the target with the bundle ID.
func (m Manifest) Target(bundleID string) (Target, bool) {
	for _, target := range m.Targets {
		if target.BundleID == bundleID {
			return target, true
		}
	}
	return Target{}, false
}
