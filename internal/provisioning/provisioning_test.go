package provisioning

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	"github.com/damian-kolasinski/crem/internal/identity"
)

// Sign wraps a property list the way Apple signs provisioning profiles.
func sign(t *testing.T, content map[string]any) []byte {
	t.Helper()
	data, err := plist.Marshal(content, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Apple"}, NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certificate, _ := x509.ParseCertificate(der)
	signed, err := pkcs7.NewSignedData(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(certificate, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	result, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestParse(t *testing.T) {
	expires := time.Date(2027, 10, 26, 12, 0, 0, 0, time.UTC)
	data := sign(t, map[string]any{
		"Name":                  "com.example.demo",
		"UUID":                  "UUID-1",
		"TeamIdentifier":        []string{"TEAM123456"},
		"ExpirationDate":        expires,
		"DeveloperCertificates": [][]byte{[]byte("certificate one")},
		"Entitlements":          map[string]any{"application-identifier": "TEAM123456.com.example.demo", "get-task-allow": false},
	})

	profile, err := Parse(data)

	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "com.example.demo" || profile.TeamID != "TEAM123456" || profile.BundleID != "com.example.demo" || !profile.ExpiresAt.Equal(expires) || profile.HasDevices || profile.GetTaskAllow {
		t.Fatalf("profile = %+v", profile)
	}
	if !slices.Equal(profile.CertificateSHA, []string{identity.Fingerprint([]byte("certificate one"))}) {
		t.Fatalf("certificates = %v", profile.CertificateSHA)
	}
}

func TestParseRecognisesAdHocProfiles(t *testing.T) {
	profile, err := Parse(sign(t, map[string]any{
		"TeamIdentifier":     []string{"TEAM123456"},
		"ProvisionedDevices": []string{"00008110-000000000000001E"},
		"Entitlements":       map[string]any{"application-identifier": "TEAM123456.com.example.demo"},
	}))
	if err != nil || !profile.HasDevices {
		t.Fatalf("profile = %+v, %v", profile, err)
	}
}

func TestParseRejectsOtherData(t *testing.T) {
	if _, err := Parse([]byte("not a profile")); err == nil {
		t.Fatal("parsed garbage")
	}
	if _, err := Parse(sign(t, map[string]any{
		"TeamIdentifier": []string{"TEAM123456"},
		"Entitlements":   map[string]any{"application-identifier": "OTHERTEAM1.com.example.demo"},
	})); err == nil {
		t.Fatal("accepted an application identifier of another team")
	}
}
