package signing

// Capability is an App ID capability, such as push notifications or App Groups, with its enabled options.
type Capability struct {
	Type     string
	Settings []CapabilitySetting
}

// CapabilitySetting is one of a capability's settings with the option keys enabled for it.
type CapabilitySetting struct {
	Key     string
	Options []string
}

// containerCapabilities need identifiers assigned in the developer portal after they are enabled.
var containerCapabilities = map[string]string{
	"APP_GROUPS": "App Groups",
	"ICLOUD":     "iCloud containers",
	"APPLE_PAY":  "Apple Pay merchant IDs",
	"WALLET":     "Wallet pass type IDs",
}

// NeedsPortalSetup names what must be assigned in the developer portal, or "" when nothing must.
func (c Capability) NeedsPortalSetup() string {
	return containerCapabilities[c.Type]
}
