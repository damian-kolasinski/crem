// Package auth signs the short-lived JWTs that authenticate App Store Connect API requests.
package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// tokenLifetime stays a minute under the 20 minutes App Store Connect accepts, so a
// slightly fast local clock does not get tokens rejected.
const tokenLifetime = 19 * time.Minute

// Key is an App Store Connect API key.
type Key struct {
	ID       string
	IssuerID string
	private  *ecdsa.PrivateKey
}

// ParseKey parses the PEM-encoded PKCS #8 .p8 file App Store Connect issues.
func ParseKey(id, issuerID string, pemData []byte) (Key, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return Key{}, errors.New("API key is not PEM-encoded")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Key{}, fmt.Errorf("API key is not a PKCS #8 private key: %w", err)
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || private.Curve != elliptic.P256() {
		return Key{}, errors.New("API key is not a P-256 key")
	}
	return Key{ID: id, IssuerID: issuerID, private: private}, nil
}

// TokenSource hands out a token, minting a new one shortly before the current one expires.
type TokenSource struct {
	key Key
	now func() time.Time

	mutex     sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTokenSource returns a TokenSource that reads time from now.
func NewTokenSource(key Key, now func() time.Time) *TokenSource {
	return &TokenSource{key: key, now: now}
}

// Token returns a bearer token valid for at least another minute.
func (s *TokenSource) Token() (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	now := s.now()
	if s.token != "" && now.Add(time.Minute).Before(s.expiresAt) {
		return s.token, nil
	}
	expiresAt := now.Add(tokenLifetime)
	token, err := sign(s.key, now, expiresAt)
	if err != nil {
		return "", err
	}
	s.token, s.expiresAt = token, expiresAt
	return token, nil
}

func sign(key Key, issuedAt, expiresAt time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": key.ID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": key.IssuerID,
		"iat": issuedAt.Unix(),
		"exp": expiresAt.Unix(),
		"aud": "appstoreconnect-v1",
	})
	if err != nil {
		return "", err
	}
	encoding := base64.RawURLEncoding
	input := encoding.EncodeToString(header) + "." + encoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key.private, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing API token: %w", err)
	}
	// JWS encodes an ES256 signature as the fixed-width concatenation r || s.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + encoding.EncodeToString(signature), nil
}
