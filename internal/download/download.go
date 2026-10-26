// Package download fetches the provisioning profiles a build signs with, as CI needs them.
package download

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/damian-kolasinski/crem/internal/provisioning"
	"github.com/damian-kolasinski/crem/internal/signing"
)

// Portal lists and downloads provisioning profiles.
type Portal interface {
	Profiles(ctx context.Context) ([]signing.Profile, error)
	ProfileContent(ctx context.Context, id string) ([]byte, error)
}

// Selection narrows the expected profiles to download.
type Selection struct {
	Kind signing.ProfileKind
	// App and Environment, when set, keep only targets of that app or environment.
	App         string
	Environment string
	// BundleIDs, when set, keep only those targets.
	BundleIDs []string
}

func (s Selection) matches(expected signing.ExpectedProfile) bool {
	target := expected.Target
	return expected.Spec.Kind == s.Kind &&
		(s.App == "" || target.App == s.App) &&
		(s.Environment == "" || target.Environment == s.Environment) &&
		(len(s.BundleIDs) == 0 || slices.Contains(s.BundleIDs, target.BundleID))
}

// Destinations are where profiles are written.
type Destinations struct {
	// Outputs receive the profiles.
	Outputs []string
	// Installs receive the profiles too, and lose any other profile file with the same name and
	// team: Xcode resolves a profile by name, and a stale one could otherwise win.
	Installs []string
}

func (d Destinations) all() []string {
	return append(slices.Clone(d.Outputs), d.Installs...)
}

// Downloaded is a profile written to disk.
type Downloaded struct {
	Expected signing.ExpectedProfile
	Profile  signing.Profile
	Paths    []string
	// Replaced are the stale profile files with the same name removed from install directories.
	Replaced []string
}

// Run downloads the current profile of every selected expected profile into each destination,
// as <uuid>.mobileprovision. It writes nothing unless every selected profile is live and is the
// profile it claims to be, so a build never signs with a partial set.
func Run(ctx context.Context, portal Portal, manifest signing.Manifest, selection Selection, destinations Destinations, now time.Time) ([]Downloaded, error) {
	if len(destinations.all()) == 0 {
		return nil, errors.New("give a directory to download into")
	}
	var selected []signing.ExpectedProfile
	for _, expected := range manifest.ExpectedProfiles() {
		if selection.matches(expected) {
			selected = append(selected, expected)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("crem.yaml expects no %s profile for that selection", selection.Kind)
	}
	for _, bundleID := range selection.BundleIDs {
		if !slices.ContainsFunc(selected, func(expected signing.ExpectedProfile) bool { return expected.Target.BundleID == bundleID }) {
			return nil, fmt.Errorf("crem.yaml expects no %s profile for %s in that selection", selection.Kind, bundleID)
		}
	}

	profiles, err := portal.Profiles(ctx)
	if err != nil {
		return nil, err
	}
	var downloads []Downloaded
	var missing []string
	for _, expected := range selected {
		current, ok := signing.CurrentProfile(profiles, expected, now)
		if !ok {
			missing = append(missing, expected.Name)
			continue
		}
		downloads = append(downloads, Downloaded{Expected: expected, Profile: current})
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("no live profile for %s; renew the profiles first", strings.Join(missing, ", "))
	}

	contents := make([][]byte, len(downloads))
	for index, item := range downloads {
		content, err := portal.ProfileContent(ctx, item.Profile.ID)
		if err != nil {
			return nil, err
		}
		parsed, err := provisioning.Parse(content)
		if err == nil {
			err = parsed.Check(provisioning.Expectation{
				Name:     item.Expected.Name,
				TeamID:   manifest.Team,
				BundleID: item.Expected.Target.BundleID,
				AdHoc:    item.Expected.Spec.Kind == signing.AdHoc,
				UUID:     item.Profile.UUID,
			}, now)
		}
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", item.Expected.Name, item.Profile.ID, err)
		}
		contents[index] = content
	}

	for index := range downloads {
		item := &downloads[index]
		name := item.Profile.UUID + ".mobileprovision"
		for _, directory := range destinations.all() {
			path := filepath.Join(directory, name)
			if err := writeAtomically(path, contents[index]); err != nil {
				return downloads[:index+1], err
			}
			item.Paths = append(item.Paths, path)
		}
		for _, directory := range destinations.Installs {
			replaced, err := removeNamesakes(directory, name, item.Expected.Name, manifest.Team)
			item.Replaced = append(item.Replaced, replaced...)
			if err != nil {
				return downloads[:index+1], err
			}
		}
	}
	return downloads, nil
}

// writeAtomically replaces path with content, never leaving a truncated file behind.
func writeAtomically(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".crem-*.mobileprovision")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// removeNamesakes deletes the other profile files in directory with the same name and team.
// Files it cannot read as profiles are left alone.
func removeNamesakes(directory, keep, name, team string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(directory, "*.mobileprovision"))
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, path := range paths {
		if filepath.Base(path) == keep {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		profile, err := provisioning.Parse(content)
		if err != nil || profile.Name != name || profile.TeamID != team {
			continue
		}
		if err := os.Remove(path); err != nil {
			return removed, err
		}
		removed = append(removed, path)
	}
	return removed, nil
}
