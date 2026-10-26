// Package provisioning reads provisioning profile files.
package provisioning

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	"github.com/damian-kolasinski/crem/internal/identity"
)

// Profile is what a .mobileprovision file says about itself.
type Profile struct {
	Name           string
	UUID           string
	TeamID         string
	BundleID       string
	ExpiresAt      time.Time
	HasDevices     bool
	GetTaskAllow   bool
	CertificateSHA []string
}

type payload struct {
	Name                  string         `plist:"Name"`
	UUID                  string         `plist:"UUID"`
	TeamIdentifier        []string       `plist:"TeamIdentifier"`
	ExpirationDate        time.Time      `plist:"ExpirationDate"`
	ProvisionedDevices    []string       `plist:"ProvisionedDevices"`
	ProvisionsAllDevices  bool           `plist:"ProvisionsAllDevices"`
	DeveloperCertificates [][]byte       `plist:"DeveloperCertificates"`
	Entitlements          map[string]any `plist:"Entitlements"`
}

// Parse reads a provisioning profile: a CMS-signed property list.
func Parse(data []byte) (Profile, error) {
	signed, err := pkcs7.Parse(data)
	if err != nil {
		return Profile{}, fmt.Errorf("not a provisioning profile: %w", err)
	}
	var content payload
	if _, err := plist.Unmarshal(signed.Content, &content); err != nil {
		return Profile{}, fmt.Errorf("unreadable provisioning profile: %w", err)
	}
	if len(content.TeamIdentifier) != 1 {
		return Profile{}, errors.New("provisioning profile does not name exactly one team")
	}
	applicationIdentifier, _ := content.Entitlements["application-identifier"].(string)
	teamID := content.TeamIdentifier[0]
	bundleID, ok := strings.CutPrefix(applicationIdentifier, teamID+".")
	if !ok {
		return Profile{}, fmt.Errorf("provisioning profile application identifier %q does not belong to team %s", applicationIdentifier, teamID)
	}
	getTaskAllow, _ := content.Entitlements["get-task-allow"].(bool)
	profile := Profile{
		Name:         content.Name,
		UUID:         content.UUID,
		TeamID:       teamID,
		BundleID:     bundleID,
		ExpiresAt:    content.ExpirationDate,
		HasDevices:   len(content.ProvisionedDevices) > 0 || content.ProvisionsAllDevices,
		GetTaskAllow: getTaskAllow,
	}
	for _, certificate := range content.DeveloperCertificates {
		profile.CertificateSHA = append(profile.CertificateSHA, identity.Fingerprint(certificate))
	}
	return profile, nil
}

// Expectation is what a profile file must say about itself.
type Expectation struct {
	Name     string
	TeamID   string
	BundleID string
	// AdHoc profiles list devices; App Store profiles must not.
	AdHoc bool
	// UUID, when set, must match: it names the file the profile is installed as.
	UUID string
	// CertificateSHA, when set, is the SHA-1 fingerprint of a certificate the profile must embed.
	CertificateSHA string
}

// Check reports how the profile differs from the expectation, or nil.
func (p Profile) Check(expect Expectation, now time.Time) error {
	switch {
	case p.Name != expect.Name:
		return fmt.Errorf("named %q, not %q", p.Name, expect.Name)
	case p.TeamID != expect.TeamID:
		return fmt.Errorf("belongs to team %s", p.TeamID)
	case p.BundleID != expect.BundleID:
		return fmt.Errorf("is for %s", p.BundleID)
	case expect.UUID != "" && p.UUID != expect.UUID:
		return fmt.Errorf("has UUID %s, not %s", p.UUID, expect.UUID)
	case p.GetTaskAllow:
		return errors.New("allows debugging, so it is not a distribution profile")
	case p.HasDevices != expect.AdHoc:
		if expect.AdHoc {
			return errors.New("lists no devices, so it is not an Ad Hoc profile")
		}
		return errors.New("lists devices, so it is not an App Store profile")
	case !p.ExpiresAt.After(now):
		return errors.New("has expired")
	case expect.CertificateSHA != "" && !slices.Contains(p.CertificateSHA, expect.CertificateSHA):
		return errors.New("does not contain the expected certificate")
	}
	return nil
}
