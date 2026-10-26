package appstoreconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/damian-kolasinski/crem/internal/signing"
)

type relationshipData struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// CreateProfile creates a provisioning profile.
func (c *Client) CreateProfile(ctx context.Context, profile signing.NewProfile) (signing.Profile, error) {
	bundleIDResource, err := c.bundleIDResource(ctx, profile.BundleID)
	if err != nil {
		return signing.Profile{}, err
	}
	relationships := map[string]any{
		"bundleId":     map[string]any{"data": relationshipData{Type: "bundleIds", ID: bundleIDResource}},
		"certificates": map[string]any{"data": []relationshipData{{Type: "certificates", ID: profile.CertificateID}}},
	}
	if len(profile.DeviceIDs) > 0 {
		devices := make([]relationshipData, len(profile.DeviceIDs))
		for index, id := range profile.DeviceIDs {
			devices[index] = relationshipData{Type: "devices", ID: id}
		}
		relationships["devices"] = map[string]any{"data": devices}
	}
	document, err := c.api.Post(ctx, "/v1/profiles", map[string]any{
		"data": map[string]any{
			"type":          "profiles",
			"attributes":    map[string]string{"name": profile.Name, "profileType": string(profile.Type)},
			"relationships": relationships,
		},
	})
	if err != nil {
		return signing.Profile{}, err
	}
	resource, err := document.Resource()
	if err != nil {
		return signing.Profile{}, fmt.Errorf("App Store Connect returned an unreadable profile: %w", err)
	}
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
		return signing.Profile{}, fmt.Errorf("App Store Connect returned profile %s without a readable expiry: %w", resource.ID, err)
	}
	createdAt, _ := parseOptionalTime(attributes.CreatedDate)
	return signing.Profile{
		ID:             resource.ID,
		Name:           attributes.Name,
		Type:           signing.ProfileType(attributes.ProfileType),
		State:          signing.ProfileState(attributes.ProfileState),
		UUID:           attributes.UUID,
		BundleID:       profile.BundleID,
		CreatedAt:      createdAt,
		ExpiresAt:      expiresAt,
		CertificateIDs: []string{profile.CertificateID},
	}, nil
}

// DeleteProfile deletes a provisioning profile.
func (c *Client) DeleteProfile(ctx context.Context, id string) error {
	return c.api.Delete(ctx, "/v1/profiles/"+url.PathEscape(id))
}

// bundleIDResource finds the API resource ID of a registered bundle ID. The identifier
// filter also matches longer identifiers, so the result is matched exactly.
func (c *Client) bundleIDResource(ctx context.Context, identifier string) (string, error) {
	data, _, err := c.api.GetAll(ctx, "/v1/bundleIds", url.Values{
		"filter[identifier]": {identifier},
		"fields[bundleIds]":  {"identifier"},
		"limit":              {"200"},
	})
	if err != nil {
		return "", err
	}
	for _, resource := range data {
		var attributes struct {
			Identifier string `json:"identifier"`
		}
		if json.Unmarshal(resource.Attributes, &attributes) == nil && attributes.Identifier == identifier {
			return resource.ID, nil
		}
	}
	return "", fmt.Errorf("bundle ID %s is not registered", identifier)
}
