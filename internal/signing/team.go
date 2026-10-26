// Package signing models an Apple developer team's code-signing state: what a
// project expects, what App Store Connect reports, and how the two differ.
package signing

import (
	"slices"
	"time"
)

// CertificateType is App Store Connect's certificate type.
type CertificateType string

const (
	CertificateTypeDistribution    CertificateType = "DISTRIBUTION"
	CertificateTypeIOSDistribution CertificateType = "IOS_DISTRIBUTION"
)

// IsDistribution reports whether certificates of this type sign App Store and Ad Hoc builds.
func (t CertificateType) IsDistribution() bool {
	return t == CertificateTypeDistribution || t == CertificateTypeIOSDistribution
}

// Certificate is a signing certificate registered with the team.
type Certificate struct {
	ID           string
	Name         string
	Type         CertificateType
	SerialNumber string
	ExpiresAt    time.Time
}

// ProfileType is App Store Connect's provisioning profile type.
type ProfileType string

const (
	ProfileTypeIOSAppStore ProfileType = "IOS_APP_STORE"
	ProfileTypeIOSAdHoc    ProfileType = "IOS_APP_ADHOC"
)

// ProfileState is App Store Connect's provisioning profile state. It stays
// ACTIVE after a profile expires; see Profile.IsLive.
type ProfileState string

const ProfileStateActive ProfileState = "ACTIVE"

// Profile is a provisioning profile registered with the team.
type Profile struct {
	ID             string
	Name           string
	Type           ProfileType
	State          ProfileState
	UUID           string
	BundleID       string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	CertificateIDs []string
}

// IsLive reports whether the profile can sign builds at now.
func (p Profile) IsLive(now time.Time) bool {
	return p.State == ProfileStateActive && p.ExpiresAt.After(now)
}

// UsesCertificate reports whether the profile embeds the certificate.
func (p Profile) UsesCertificate(id string) bool {
	return slices.Contains(p.CertificateIDs, id)
}

// BundleID is a registered App ID.
type BundleID struct {
	Identifier string
	Name       string
}

// DeviceClass is the kind of a registered device.
type DeviceClass string

// Device is a registered test device.
type Device struct {
	ID    string
	Name  string
	UDID  string
	Class DeviceClass
}

// AdHocDeviceClasses are the device classes Ad Hoc iOS profiles can include.
var AdHocDeviceClasses = []DeviceClass{"IPHONE", "IPAD", "IPOD"}
