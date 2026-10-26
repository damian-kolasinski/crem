// Package local keeps signing identities in a private directory on this machine.
package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/damian-kolasinski/crem/internal/vault"
)

// Each identity lives in <root>/<certificate ID>/ as these files.
const (
	p12File      = "identity.p12"
	passwordFile = "password"
	metadataFile = "identity.json"
)

var certificateIDPattern = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// Vault is a directory of identities.
type Vault struct {
	root string
}

// New returns a vault rooted at the absolute path root.
func New(root string) *Vault {
	return &Vault{root: root}
}

func (v *Vault) Describe() string {
	return "local " + v.root
}

type metadata struct {
	Team          string    `json:"team"`
	CertificateID string    `json:"certificateId"`
	SerialNumber  string    `json:"serialNumber"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

func (v *Vault) directory(certificateID string) (string, error) {
	if !certificateIDPattern.MatchString(certificateID) {
		return "", fmt.Errorf("invalid certificate ID %q", certificateID)
	}
	return filepath.Join(v.root, certificateID), nil
}

// Save writes the identity into a new directory, all or nothing.
func (v *Vault) Save(_ context.Context, entry vault.Entry) error {
	target, err := v.directory(entry.CertificateID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("%s: %w", target, vault.ErrExists)
	}
	if err := os.MkdirAll(v.root, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(v.root, ".saving-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	metadataJSON, err := json.MarshalIndent(metadata{Team: entry.Team, CertificateID: entry.CertificateID, SerialNumber: entry.SerialNumber, ExpiresAt: entry.ExpiresAt.UTC()}, "", "  ")
	if err != nil {
		return err
	}
	for name, content := range map[string][]byte{
		p12File:      entry.P12,
		passwordFile: []byte(entry.Password),
		metadataFile: append(metadataJSON, '\n'),
	} {
		if err := writeDurably(filepath.Join(staging, name), content); err != nil {
			return err
		}
	}
	if err := syncDirectory(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, target); err != nil {
		if _, statErr := os.Stat(target); statErr == nil {
			return fmt.Errorf("%s: %w", target, vault.ErrExists)
		}
		return err
	}
	return syncDirectory(v.root)
}

// writeDurably creates a private file and flushes it to disk, since it may hold the only copy of a key.
func writeDurably(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (v *Vault) Load(_ context.Context, team, certificateID string) (vault.Entry, error) {
	directory, err := v.directory(certificateID)
	if err != nil {
		return vault.Entry{}, err
	}
	meta, err := readMetadata(directory)
	if errors.Is(err, os.ErrNotExist) || (err == nil && meta.Team != team) {
		return vault.Entry{}, fmt.Errorf("%s in %s: %w", certificateID, v.Describe(), vault.ErrNotFound)
	}
	if err != nil {
		return vault.Entry{}, err
	}
	p12, err := os.ReadFile(filepath.Join(directory, p12File))
	if err != nil {
		return vault.Entry{}, err
	}
	password, err := os.ReadFile(filepath.Join(directory, passwordFile))
	if err != nil {
		return vault.Entry{}, err
	}
	return vault.Entry{Team: meta.Team, CertificateID: meta.CertificateID, SerialNumber: meta.SerialNumber, ExpiresAt: meta.ExpiresAt, P12: p12, Password: string(password)}, nil
}

func (v *Vault) List(_ context.Context, team string) ([]string, error) {
	entries, err := os.ReadDir(v.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, vault.ErrNotSetUp
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if !entry.IsDir() || !certificateIDPattern.MatchString(entry.Name()) {
			continue
		}
		meta, err := readMetadata(filepath.Join(v.root, entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if meta.Team == team {
			ids = append(ids, meta.CertificateID)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

func readMetadata(directory string) (metadata, error) {
	data, err := os.ReadFile(filepath.Join(directory, metadataFile))
	if err != nil {
		return metadata{}, err
	}
	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return metadata{}, fmt.Errorf("%s: %w", filepath.Join(directory, metadataFile), err)
	}
	return meta, nil
}
