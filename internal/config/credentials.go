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
	KeyID    string
	IssuerID string
	// PrivateKeyEnv names an environment variable holding the .p8 contents.
	PrivateKeyEnv string
	// PrivateKeyPath is the .p8 file, relative to the config file.
	PrivateKeyPath string
}

// Environment is the process environment and file system the key is looked up in.
type Environment struct {
	Getenv     func(string) string
	HomeDir    string
	WorkingDir string
	ConfigDir  string
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
		candidates = append(candidates, expandPath(c.PrivateKeyPath, environment.HomeDir, environment.ConfigDir))
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
