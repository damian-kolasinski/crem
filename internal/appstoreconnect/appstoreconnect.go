// Package appstoreconnect is the App Store Connect adapter: it reads and changes
// a team's certificates, bundle IDs, devices, and provisioning profiles.
package appstoreconnect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/damian-kolasinski/crem/internal/appstoreconnect/jsonapi"
	"github.com/damian-kolasinski/crem/internal/signing"
)

// Client is a team's App Store Connect account.
type Client struct {
	api *jsonapi.Client
}

// New returns a Client that sends requests through api.
func New(api *jsonapi.Client) *Client {
	return &Client{api: api}
}

// Certificates lists the team's certificates. App Store Connect omits expired and revoked ones.
func (c *Client) Certificates(ctx context.Context) ([]signing.Certificate, error) {
	data, _, err := c.api.GetAll(ctx, "/v1/certificates", url.Values{
		"limit":                {"200"},
		"fields[certificates]": {"name,certificateType,serialNumber,expirationDate"},
	})
	if err != nil {
		return nil, err
	}
	return mapEach(data, certificate)
}

func certificate(resource jsonapi.Resource) (signing.Certificate, error) {
	var attributes struct {
		Name            string `json:"name"`
		CertificateType string `json:"certificateType"`
		SerialNumber    string `json:"serialNumber"`
		ExpirationDate  string `json:"expirationDate"`
	}
	if err := json.Unmarshal(resource.Attributes, &attributes); err != nil {
		return signing.Certificate{}, err
	}
	expiresAt, err := parseTime(attributes.ExpirationDate)
	if err != nil {
		return signing.Certificate{}, err
	}
	return signing.Certificate{
		ID:           resource.ID,
		Name:         attributes.Name,
		Type:         signing.CertificateType(attributes.CertificateType),
		SerialNumber: attributes.SerialNumber,
		ExpiresAt:    expiresAt,
	}, nil
}

// CreateCertificate creates an Apple Distribution certificate for the PEM-encoded
// certificate signing request and returns it with its DER encoding.
func (c *Client) CreateCertificate(ctx context.Context, csrPEM []byte) (signing.Certificate, []byte, error) {
	document, err := c.api.Post(ctx, "/v1/certificates", map[string]any{
		"data": map[string]any{
			"type": "certificates",
			"attributes": map[string]string{
				"certificateType": string(signing.CertificateTypeDistribution),
				"csrContent":      string(csrPEM),
			},
		},
	})
	if err != nil {
		return signing.Certificate{}, nil, err
	}
	resource, err := document.Resource()
	if err != nil {
		return signing.Certificate{}, nil, fmt.Errorf("App Store Connect returned an unreadable certificate: %w", err)
	}
	created, err := certificate(resource)
	if err != nil {
		// Keep the ID: the certificate exists and its key must not be forgotten.
		return signing.Certificate{ID: resource.ID}, nil, fmt.Errorf("App Store Connect returned an unreadable certificate %s: %w", resource.ID, err)
	}
	var content struct {
		CertificateContent string `json:"certificateContent"`
	}
	var der []byte
	if json.Unmarshal(resource.Attributes, &content) == nil {
		der, _ = base64.StdEncoding.DecodeString(content.CertificateContent)
	}
	if len(der) == 0 {
		der, err = c.certificateContent(ctx, resource.ID)
		if err != nil {
			return created, nil, err
		}
	}
	return created, der, nil
}

// RevokeCertificate revokes a certificate.
func (c *Client) RevokeCertificate(ctx context.Context, id string) error {
	return c.api.Delete(ctx, "/v1/certificates/"+url.PathEscape(id))
}

// certificateContent fetches a certificate's DER encoding.
func (c *Client) certificateContent(ctx context.Context, id string) ([]byte, error) {
	data, _, err := c.api.GetAll(ctx, "/v1/certificates", url.Values{
		"filter[id]":           {id},
		"fields[certificates]": {"certificateContent"},
	})
	if err != nil {
		return nil, err
	}
	for _, resource := range data {
		var content struct {
			CertificateContent string `json:"certificateContent"`
		}
		if resource.ID != id || json.Unmarshal(resource.Attributes, &content) != nil {
			continue
		}
		if der, err := base64.StdEncoding.DecodeString(content.CertificateContent); err == nil && len(der) > 0 {
			return der, nil
		}
	}
	return nil, fmt.Errorf("App Store Connect returned certificate %s without readable content", id)
}

// BundleIDs lists the team's registered bundle IDs.
func (c *Client) BundleIDs(ctx context.Context) ([]signing.BundleID, error) {
	data, _, err := c.api.GetAll(ctx, "/v1/bundleIds", url.Values{
		"limit":             {"200"},
		"fields[bundleIds]": {"identifier,name"},
	})
	if err != nil {
		return nil, err
	}
	return mapEach(data, func(resource jsonapi.Resource) (signing.BundleID, error) {
		var attributes struct {
			Identifier string `json:"identifier"`
			Name       string `json:"name"`
		}
		err := json.Unmarshal(resource.Attributes, &attributes)
		return signing.BundleID{Identifier: attributes.Identifier, Name: attributes.Name}, err
	})
}

// Profiles lists the team's provisioning profiles, including expired ones.
func (c *Client) Profiles(ctx context.Context) ([]signing.Profile, error) {
	data, included, err := c.api.GetAll(ctx, "/v1/profiles", url.Values{
		"limit":                {"200"},
		"include":              {"bundleId,certificates"},
		"limit[certificates]":  {"50"},
		"fields[certificates]": {"certificateType"},
		"fields[profiles]":     {"name,profileType,profileState,uuid,createdDate,expirationDate,bundleId,certificates"},
		"fields[bundleIds]":    {"identifier"},
	})
	if err != nil {
		return nil, err
	}
	bundleIDs := map[string]string{}
	for _, resource := range included {
		if resource.Type != "bundleIds" {
			continue
		}
		var attributes struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(resource.Attributes, &attributes); err != nil {
			return nil, err
		}
		bundleIDs[resource.ID] = attributes.Identifier
	}
	return mapEach(data, func(resource jsonapi.Resource) (signing.Profile, error) {
		var attributes struct {
			Name           string `json:"name"`
			ProfileType    string `json:"profileType"`
			ProfileState   string `json:"profileState"`
			UUID           string `json:"uuid"`
			CreatedDate    string `json:"createdDate"`
			ExpirationDate string `json:"expirationDate"`
		}
		if err := json.Unmarshal(resource.Attributes, &attributes); err != nil {
			return signing.Profile{}, err
		}
		expiresAt, err := parseTime(attributes.ExpirationDate)
		if err != nil {
			return signing.Profile{}, err
		}
		createdAt, err := parseOptionalTime(attributes.CreatedDate)
		if err != nil {
			return signing.Profile{}, err
		}
		var bundleID string
		if ids := resource.Relationships["bundleId"].IDs(); len(ids) == 1 {
			bundleID = bundleIDs[ids[0]]
		}
		return signing.Profile{
			ID:             resource.ID,
			Name:           attributes.Name,
			Type:           signing.ProfileType(attributes.ProfileType),
			State:          signing.ProfileState(attributes.ProfileState),
			UUID:           attributes.UUID,
			BundleID:       bundleID,
			CreatedAt:      createdAt,
			ExpiresAt:      expiresAt,
			CertificateIDs: resource.Relationships["certificates"].IDs(),
		}, nil
	})
}

// AdHocDevices lists the enabled devices iOS Ad Hoc profiles can include.
func (c *Client) AdHocDevices(ctx context.Context) ([]signing.Device, error) {
	data, _, err := c.api.GetAll(ctx, "/v1/devices", url.Values{
		"limit":            {"200"},
		"filter[platform]": {"IOS"},
		"filter[status]":   {"ENABLED"},
		"fields[devices]":  {"name,udid,deviceClass"},
	})
	if err != nil {
		return nil, err
	}
	devices, err := mapEach(data, device)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(devices, func(device signing.Device) bool {
		return !slices.Contains(signing.AdHocDeviceClasses, device.Class)
	}), nil
}

// ProfileDevices lists the devices a profile includes.
func (c *Client) ProfileDevices(ctx context.Context, profileID string) ([]signing.Device, error) {
	data, _, err := c.api.GetAll(ctx, "/v1/profiles/"+url.PathEscape(profileID)+"/devices", url.Values{
		"limit":           {"200"},
		"fields[devices]": {"name,udid,deviceClass"},
	})
	if err != nil {
		return nil, err
	}
	return mapEach(data, device)
}

func device(resource jsonapi.Resource) (signing.Device, error) {
	var attributes struct {
		Name        string `json:"name"`
		UDID        string `json:"udid"`
		DeviceClass string `json:"deviceClass"`
	}
	err := json.Unmarshal(resource.Attributes, &attributes)
	return signing.Device{ID: resource.ID, Name: attributes.Name, UDID: attributes.UDID, Class: signing.DeviceClass(attributes.DeviceClass)}, err
}

func mapEach[T any](resources []jsonapi.Resource, convert func(jsonapi.Resource) (T, error)) ([]T, error) {
	result := make([]T, 0, len(resources))
	for _, resource := range resources {
		value, err := convert(resource)
		if err != nil {
			return nil, fmt.Errorf("App Store Connect returned an unreadable %s %s: %w", resource.Type, resource.ID, err)
		}
		result = append(result, value)
	}
	return result, nil
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, value)
}

func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return parseTime(value)
}
