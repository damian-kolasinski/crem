// Package config reads crem.yaml into the signing state a project expects and
// the App Store Connect credentials it uses.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/damian-kolasinski/crem/internal/signing"
)

// FileName is the config file crem looks for.
const FileName = "crem.yaml"

// Config is a validated crem.yaml.
type Config struct {
	Path            string
	Manifest        signing.Manifest
	AppStoreConnect AppStoreConnect
}

type file struct {
	Team            string          `yaml:"team"`
	AppStoreConnect appStoreConnect `yaml:"appStoreConnect"`
	Profiles        []profileSpec   `yaml:"profiles"`
	Apps            []app           `yaml:"apps"`
	Cleanup         *scope          `yaml:"cleanup"`
}

type appStoreConnect struct {
	KeyID          string `yaml:"keyId"`
	IssuerID       string `yaml:"issuerId"`
	PrivateKeyEnv  string `yaml:"privateKeyEnv"`
	PrivateKeyPath string `yaml:"privateKeyPath"`
}

type profileSpec struct {
	Kind    string `yaml:"kind"`
	Name    string `yaml:"name"`
	Devices string `yaml:"devices"`
}

type app struct {
	Name         string            `yaml:"name"`
	Environments orderedMap        `yaml:"environments"`
	Extensions   []string          `yaml:"extensions"`
	Secrets      map[string]string `yaml:"secrets"`
}

type scope struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

type orderedMap []keyValue

type keyValue struct{ key, value string }

func (m *orderedMap) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping of environment names to bundle IDs", node.Line)
	}
	for index := 0; index < len(node.Content); index += 2 {
		key, value := node.Content[index], node.Content[index+1]
		if key.Value == "" {
			return fmt.Errorf("line %d: environment names cannot be empty", key.Line)
		}
		if slices.ContainsFunc(*m, func(existing keyValue) bool { return existing.key == key.Value }) {
			return fmt.Errorf("line %d: environment %q is listed twice", key.Line, key.Value)
		}
		if value.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: bundle ID for %q must be a string", value.Line, key.Value)
		}
		*m = append(*m, keyValue{key.Value, value.Value})
	}
	return nil
}

// Find returns the path of the nearest crem.yaml in directory or its ancestors.
func Find(directory string) (string, error) {
	for current := directory; ; {
		candidate := filepath.Join(current, FileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no %s in %s or its parent directories", FileName, directory)
		}
		current = parent
	}
}

// Load reads and validates a config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	config, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	config.Path = path
	return config, nil
}

var (
	bundleIDPattern   = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	extensionPattern  = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	identifierPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Parse validates config file contents.
func Parse(data []byte) (Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var raw file
	if err := decoder.Decode(&raw); errors.Is(err, io.EOF) {
		return Config{}, errors.New("the file is empty")
	} else if err != nil {
		return Config{}, fmt.Errorf("invalid YAML: %w", err)
	}

	var problems []string
	problem := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if !identifierPattern.MatchString(raw.Team) {
		problem("team: must be a 10-character team ID")
	}
	connect := AppStoreConnect{
		KeyID:          raw.AppStoreConnect.KeyID,
		IssuerID:       raw.AppStoreConnect.IssuerID,
		PrivateKeyEnv:  raw.AppStoreConnect.PrivateKeyEnv,
		PrivateKeyPath: raw.AppStoreConnect.PrivateKeyPath,
	}
	if !identifierPattern.MatchString(connect.KeyID) {
		problem("appStoreConnect.keyId: must be a 10-character API key ID")
	}
	if !uuidPattern.MatchString(connect.IssuerID) {
		problem("appStoreConnect.issuerId: must be the issuer ID (a UUID) shown above the API keys in App Store Connect")
	}

	manifest := signing.Manifest{Team: raw.Team}
	if len(raw.Profiles) == 0 {
		problem("profiles: list at least one profile kind")
	}
	for index, spec := range raw.Profiles {
		at := fmt.Sprintf("profiles[%d]", index)
		kind, err := signing.ParseProfileKind(spec.Kind)
		if err != nil {
			problem("%s.kind: %v", at, err)
			continue
		}
		if slices.ContainsFunc(manifest.Profiles, func(existing signing.ProfileSpec) bool { return existing.Kind == kind }) {
			problem("%s.kind: %s is listed twice", at, kind)
		}
		name, err := signing.ParseTemplate(spec.Name)
		if err != nil {
			problem("%s.name: %v", at, err)
		} else if !name.Uses("bundleId") {
			problem("%s.name: must include {bundleId} so every profile name is unique", at)
		}
		devices := signing.DeviceSelection(0)
		switch {
		case kind == signing.AdHoc:
			devices = signing.CarryOverDevices
			if spec.Devices != "" {
				if devices, err = signing.ParseDeviceSelection(spec.Devices); err != nil {
					problem("%s.devices: %v", at, err)
				}
			}
		case spec.Devices != "":
			problem("%s.devices: only ad-hoc profiles include devices", at)
		}
		manifest.Profiles = append(manifest.Profiles, signing.ProfileSpec{Kind: kind, Name: name, Devices: devices})
	}

	if len(raw.Apps) == 0 {
		problem("apps: list at least one app")
	}
	seenBundleIDs := map[string]string{}
	var defaultScope []string
	for appIndex, app := range raw.Apps {
		at := fmt.Sprintf("apps[%d]", appIndex)
		if app.Name == "" {
			problem("%s.name: required", at)
		}
		if len(app.Environments) == 0 {
			problem("%s.environments: map at least one environment to its bundle ID", at)
		}
		for _, extension := range app.Extensions {
			if !extensionPattern.MatchString(extension) || extension == "app" {
				problem("%s.extensions: %q is not a valid extension suffix", at, extension)
			}
		}
		secrets := map[string]signing.Template{}
		for _, component := range slices.Sorted(maps.Keys(app.Secrets)) {
			if component != "app" && !slices.Contains(app.Extensions, component) {
				problem("%s.secrets.%s: not \"app\" or one of the app's extensions", at, component)
				continue
			}
			template, err := signing.ParseTemplate(app.Secrets[component])
			if err != nil {
				problem("%s.secrets.%s: %v", at, component, err)
				continue
			}
			if len(app.Environments) > 1 && !template.Uses("environment") && !template.Uses("bundleId") {
				problem("%s.secrets.%s: must include {environment} because the app has several environments", at, component)
			}
			secrets[component] = template
		}
		for _, environment := range app.Environments {
			if !bundleIDPattern.MatchString(environment.value) {
				problem("%s.environments.%s: %q is not an explicit bundle ID", at, environment.key, environment.value)
				continue
			}
			defaultScope = append(defaultScope, environment.value)
			for _, extension := range append([]string{""}, app.Extensions...) {
				target := signing.Target{App: app.Name, Environment: environment.key, Extension: extension, BundleID: environment.value}
				if extension != "" {
					target.BundleID += "." + extension
				}
				if previous, seen := seenBundleIDs[target.BundleID]; seen {
					problem("%s.environments.%s: bundle ID %s is also used by %s", at, environment.key, target.BundleID, previous)
					continue
				}
				seenBundleIDs[target.BundleID] = at
				if template, ok := secrets[target.Component()]; ok {
					target.Secret = template.Render(map[string]string{"app": target.App, "environment": target.Environment, "extension": target.Extension, "bundleId": target.BundleID})
				}
				manifest.Targets = append(manifest.Targets, target)
			}
		}
	}

	manifest.Cleanup = signing.Scope{Include: defaultScope}
	if raw.Cleanup != nil {
		manifest.Cleanup = signing.Scope{Include: raw.Cleanup.Include, Exclude: raw.Cleanup.Exclude}
		if len(raw.Cleanup.Include) == 0 {
			problem("cleanup.include: list at least one bundle ID prefix, or omit cleanup to use the apps' bundle IDs")
		}
	}
	for _, target := range manifest.Targets {
		if !manifest.Cleanup.Contains(target.BundleID) {
			problem("cleanup: managed bundle ID %s is outside the cleanup scope, so its superseded profiles could never be removed", target.BundleID)
		}
	}

	names := map[string]string{}
	for _, expected := range manifest.ExpectedProfiles() {
		owner := fmt.Sprintf("the %s profile of %s", expected.Spec.Kind, expected.Target.BundleID)
		if previous, seen := names[expected.Name]; seen {
			problem("profiles: %s and %s would both be named %q", previous, owner, expected.Name)
		}
		names[expected.Name] = owner
	}
	secretOwners := map[string]string{}
	for _, target := range manifest.Targets {
		if target.Secret == "" {
			continue
		}
		if previous, seen := secretOwners[target.Secret]; seen {
			problem("apps: %s and %s would both use the secret %s", previous, target.BundleID, target.Secret)
		}
		secretOwners[target.Secret] = target.BundleID
	}

	if len(problems) > 0 {
		return Config{}, errors.New(strings.Join(problems, "\n"))
	}
	return Config{Manifest: manifest, AppStoreConnect: connect}, nil
}
