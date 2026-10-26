package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// issue plays Apple: it signs the CSR's public key into a certificate.
func issue(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("not a PEM CSR: %q", csrPEM)
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	authority, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Apple Distribution: Example"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, request.PublicKey, authority)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestIdentityRoundTripsThroughP12(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := Request(key, "crem")
	if err != nil {
		t.Fatal(err)
	}
	certificate := issue(t, csr)

	created, err := New(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := NewPassword()
	p12, err := created.P12(password)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(p12, password)

	if err != nil || opened.Fingerprint() != created.Fingerprint() || len(created.Fingerprint()) != 40 {
		t.Fatalf("opened = %v, %v", opened.Fingerprint(), err)
	}
	if _, err := Open(p12, "wrong"); err == nil {
		t.Fatal("opened with the wrong password")
	}
}

func TestNewRejectsACertificateForAnotherKey(t *testing.T) {
	key, _ := NewKey()
	other, _ := NewKey()
	csr, _ := Request(other, "crem")

	if _, err := New(issue(t, csr), key); err == nil {
		t.Fatal("paired a certificate with the wrong key")
	}
}
