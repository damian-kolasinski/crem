package appstoreconnect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/damian-kolasinski/crem/internal/signing"
)

// BundleIDCapabilities lists a registered bundle ID's capabilities with their enabled options.
func (c *Client) BundleIDCapabilities(ctx context.Context, identifier string) ([]signing.Capability, error) {
	resourceID, err := c.bundleIDResource(ctx, identifier)
	if err != nil {
		return nil, err
	}
	data, _, err := c.api.GetAll(ctx, "/v1/bundleIds/"+url.PathEscape(resourceID)+"/bundleIdCapabilities", nil)
	if err != nil {
		return nil, err
	}
	capabilities := make([]signing.Capability, 0, len(data))
	for _, resource := range data {
		var attributes struct {
			CapabilityType string `json:"capabilityType"`
			Settings       []struct {
				Key     string `json:"key"`
				Options []struct {
					Key     string `json:"key"`
					Enabled bool   `json:"enabled"`
				} `json:"options"`
			} `json:"settings"`
		}
		if err := json.Unmarshal(resource.Attributes, &attributes); err != nil {
			return nil, fmt.Errorf("App Store Connect returned an unreadable capability of %s: %w", identifier, err)
		}
		capability := signing.Capability{Type: attributes.CapabilityType}
		for _, setting := range attributes.Settings {
			var options []string
			for _, option := range setting.Options {
				if option.Enabled {
					options = append(options, option.Key)
				}
			}
			if len(options) > 0 {
				capability.Settings = append(capability.Settings, signing.CapabilitySetting{Key: setting.Key, Options: options})
			}
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}

// RegisterBundleID registers an explicit iOS bundle ID.
func (c *Client) RegisterBundleID(ctx context.Context, identifier, name string) error {
	_, err := c.api.Post(ctx, "/v1/bundleIds", map[string]any{
		"data": map[string]any{
			"type":       "bundleIds",
			"attributes": map[string]string{"identifier": identifier, "name": name, "platform": "IOS"},
		},
	})
	return err
}

// EnableCapability enables a capability on a registered bundle ID.
func (c *Client) EnableCapability(ctx context.Context, identifier string, capability signing.Capability) error {
	resourceID, err := c.bundleIDResource(ctx, identifier)
	if err != nil {
		return err
	}
	attributes := map[string]any{"capabilityType": capability.Type}
	settings := capability.Settings
	// The API omits Sign in with Apple's settings on read but requires a consent setting on write.
	if capability.Type == "APPLE_ID_AUTH" && len(settings) == 0 {
		settings = []signing.CapabilitySetting{{Key: "APPLE_ID_AUTH_APP_CONSENT", Options: []string{"PRIMARY_APP_CONSENT"}}}
	}
	if len(settings) > 0 {
		var encoded []map[string]any
		for _, setting := range settings {
			var options []map[string]any
			for _, option := range setting.Options {
				options = append(options, map[string]any{"key": option, "enabled": true})
			}
			encoded = append(encoded, map[string]any{"key": setting.Key, "options": options})
		}
		attributes["settings"] = encoded
	}
	_, err = c.api.Post(ctx, "/v1/bundleIdCapabilities", map[string]any{
		"data": map[string]any{
			"type":          "bundleIdCapabilities",
			"attributes":    attributes,
			"relationships": map[string]any{"bundleId": map[string]any{"data": relationshipData{Type: "bundleIds", ID: resourceID}}},
		},
	})
	return err
}
