// Package vault defines where crem keeps signing identities.
package vault

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound means the vault holds no identity for the certificate.
var ErrNotFound = errors.New("identity not found in vault")

// ErrExists means the vault already holds an identity for the certificate; vaults never replace one.
var ErrExists = errors.New("vault already holds an identity for this certificate")

// ErrNotSetUp means the vault does not exist on this machine yet; saving creates it.
var ErrNotSetUp = errors.New("vault is not set up on this machine")

// Entry is a signing identity as a vault stores it.
type Entry struct {
	Team          string
	CertificateID string
	SerialNumber  string
	ExpiresAt     time.Time
	// P12 holds the certificate and its private key, encrypted with Password.
	P12      []byte
	Password string
}

// Vault stores signing identities by team and App Store Connect certificate ID.
type Vault interface {
	// Describe names the vault for people, without secrets.
	Describe() string
	Save(ctx context.Context, entry Entry) error
	Load(ctx context.Context, team, certificateID string) (Entry, error)
	// List returns the IDs of the certificates the vault holds identities for.
	List(ctx context.Context, team string) ([]string, error)
}
