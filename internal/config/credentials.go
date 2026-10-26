package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppStoreConnect locates the App Store Connect API key crem signs requests with.
type AppStoreConnect struct {
	// KeyID and IssuerID are given in the config, or read from the variables KeyIDEnv and IssuerIDEnv.
	KeyID       string
	KeyIDEnv    string
	IssuerID    string
	IssuerIDEnv string
	// PrivateKeyEnv names an environment variable holding the .p8 contents.
	PrivateKeyEnv string
	// PrivateKeyPath is the .p8 file, relative to the config file; {keyId} stands for the key ID.
	PrivateKeyPath string
}

// Environment is the process environment and file system the key is looked up in.
type Environment struct {
	Getenv     func(string) string
	HomeDir    string
	WorkingDir string
	ConfigDir  string
}

const (
	keyIDProblem    = "must be a 10-character API key ID"
	issuerIDProblem = "must be the issuer ID (a UUID) shown above the API keys in App Store Connect"
)

// Resolve fills in the key and issuer IDs read from the environment.
func (c AppStoreConnect) Resolve(environment Environment) (AppStoreConnect, error) {
	if c.KeyIDEnv != "" {
		c.KeyID = environment.Getenv(c.KeyIDEnv)
		if !identifierPattern.MatchString(c.KeyID) {
			return c, fmt.Errorf("$%s %s", c.KeyIDEnv, keyIDProblem)
		}
	}
	if c.IssuerIDEnv != "" {
		c.IssuerID = environment.Getenv(c.IssuerIDEnv)
		if !uuidPattern.MatchString(c.IssuerID) {
			return c, fmt.Errorf("$%s %s", c.IssuerIDEnv, issuerIDProblem)
		}
	}
	return c, nil
}

// PrivateKey returns the .p8 contents and where they came from. It tries, in order,
// privateKeyEnv, privateKeyPath, and AuthKey_<keyId>.p8 in the directories altool searches.
func (c AppStoreConnect) PrivateKey(environment Environment) ([]byte, string, error) {
	if c.PrivateKeyEnv != "" {
		if value := environment.Getenv(c.PrivateKeyEnv); value != "" {
			// CI systems often store multi-line keys with escaped newlines.
			return []byte(strings.ReplaceAll(value, `\n`, "\n")), "$" + c.PrivateKeyEnv, nil
		}
	}
	var candidates []string
	if c.PrivateKeyPath != "" {
		path := strings.ReplaceAll(c.PrivateKeyPath, "{keyId}", c.KeyID)
		candidates = append(candidates, expandPath(path, environment.HomeDir, environment.ConfigDir))
	} else {
		name := "AuthKey_" + c.KeyID + ".p8"
		candidates = append(candidates,
			filepath.Join(environment.WorkingDir, "private_keys", name),
			filepath.Join(environment.HomeDir, "private_keys", name),
			filepath.Join(environment.HomeDir, ".private_keys", name),
			filepath.Join(environment.HomeDir, ".appstoreconnect", "private_keys", name),
		)
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err == nil {
			return data, candidate, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}
	}
	tried := candidates
	if c.PrivateKeyEnv != "" {
		tried = append([]string{"$" + c.PrivateKeyEnv}, tried...)
	}
	return nil, "", fmt.Errorf("App Store Connect API key %s not found; tried %s", c.KeyID, strings.Join(tried, ", "))
}

func expandPath(path, home, base string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		return filepath.Join(home, strings.TrimPrefix(path, "~"))
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
