package local

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/damian-kolasinski/crem/internal/vault"
)

// Recovery keeps what could otherwise be lost while a certificate is being created:
// the private key from before Apple is asked to issue the certificate, and the identity
// when no configured vault could save it. It lives in the user's home directory and is
// never consulted as a vault.
type Recovery struct {
	root       string
	identities *Vault
}

// NewRecovery returns a recovery store rooted at the absolute path root.
func NewRecovery(root string) *Recovery {
	return &Recovery{root: root, identities: New(filepath.Join(root, "identities"))}
}

func (r *Recovery) Describe() string {
	return "local " + r.root
}

// KeepKey writes a PEM private key durably and returns its path.
func (r *Recovery) KeepKey(team string, keyPEM []byte) (string, error) {
	directory := filepath.Join(r.root, "keys")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	path := filepath.Join(directory, fmt.Sprintf("%s-%s-%s.key.pem", team, time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(random)))
	if err := writeDurably(path, keyPEM); err != nil {
		return "", err
	}
	return path, syncDirectory(directory)
}

// Discard removes a key KeepKey wrote, once its identity is safely stored elsewhere.
func (r *Recovery) Discard(path string) error {
	return os.Remove(path)
}

// Save keeps an identity no vault could save.
func (r *Recovery) Save(ctx context.Context, entry vault.Entry) error {
	return r.identities.Save(ctx, entry)
}

// Location names where Save keeps an identity.
func (r *Recovery) Location(certificateID string) string {
	return filepath.Join(r.identities.root, certificateID)
}
