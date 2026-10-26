// Package provisioning reads provisioning profile files.
package provisioning

import (
	"errors"
	"fmt"
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
