// Package identity creates signing identities: a private key, the certificate
// signing request Apple issues a certificate for, and the .p12 that carries both.
package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// Apple issues signing certificates for 2048-bit RSA keys.
const keyBits = 2048

// NewKey generates a private key for a new certificate.
func NewKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyBits)
}

// Request returns a PEM-encoded certificate signing request for the key.
func Request(key *rsa.PrivateKey, commonName string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate signing request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// EncodeKey returns the key as a PEM-encoded PKCS #8 private key.
func EncodeKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Identity is a certificate with its private key.
type Identity struct {
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
}

// New pairs an issued certificate with the key it was requested for.
func New(certificateDER []byte, key *rsa.PrivateKey) (Identity, error) {
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return Identity{}, fmt.Errorf("reading issued certificate: %w", err)
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) {
		return Identity{}, errors.New("the issued certificate does not match the private key")
	}
	return Identity{Certificate: certificate, Key: key}, nil
}

// Fingerprint is the certificate's SHA-1 fingerprint, as provisioning profiles and keychains show it.
func (i Identity) Fingerprint() string {
	return Fingerprint(i.Certificate.Raw)
}

// Fingerprint returns the uppercase hex SHA-1 of a DER certificate.
func Fingerprint(certificateDER []byte) string {
	sum := sha1.Sum(certificateDER)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// NewPassword returns a random .p12 password.
func NewPassword() (string, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

// P12 encodes the identity as a password-protected PKCS #12 file. It uses the
// legacy 3DES encryption every version of macOS's keychain imports, and decodes
// the result again to prove it round-trips.
func (i Identity) P12(password string) ([]byte, error) {
	data, err := pkcs12.LegacyDES.Encode(i.Key, i.Certificate, nil, password)
	if err != nil {
		return nil, fmt.Errorf("encoding .p12: %w", err)
	}
	decoded, err := Open(data, password)
	if err != nil {
		return nil, fmt.Errorf("verifying .p12: %w", err)
	}
	if !bytes.Equal(decoded.Certificate.Raw, i.Certificate.Raw) || !decoded.Key.Equal(i.Key) {
		return nil, errors.New("verifying .p12: it does not contain the identity it was made from")
	}
	return data, nil
}

// Open decodes a .p12 holding one RSA identity.
func Open(p12 []byte, password string) (Identity, error) {
	key, certificate, _, err := pkcs12.DecodeChain(p12, password)
	if err != nil {
		return Identity{}, fmt.Errorf("opening .p12: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return Identity{}, errors.New("opening .p12: the private key is not RSA")
	}
	return New(certificate.Raw, rsaKey)
}
