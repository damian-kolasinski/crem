package publish

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"howett.net/plist"

	"github.com/damian-kolasinski/crem/internal/identity"
	"github.com/damian-kolasinski/crem/internal/secretstore"
	"github.com/damian-kolasinski/crem/internal/signing"
	"github.com/damian-kolasinski/crem/internal/vault"
	"github.com/damian-kolasinski/crem/internal/vault/local"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func days(n int) time.Time { return now.Add(time.Duration(n) * 24 * time.Hour) }

type team struct {
	certificates []signing.Certificate
	profiles     []signing.Profile
	content      map[string][]byte
}

func (t *team) Certificates(context.Context) ([]signing.Certificate, error) {
	return t.certificates, nil
}
func (t *team) BundleIDs(context.Context) ([]signing.BundleID, error) {
	return []signing.BundleID{{Identifier: "com.example.demo"}, {Identifier: "com.example.demo.share"}}, nil
}
func (t *team) Profiles(context.Context) ([]signing.Profile, error)    { return t.profiles, nil }
func (t *team) AdHocDevices(context.Context) ([]signing.Device, error) { return nil, nil }
func (t *team) ProfileDevices(context.Context, string) ([]signing.Device, error) {
	return nil, nil
}
func (t *team) ProfileContent(_ context.Context, id string) ([]byte, error) {
	return t.content[id], nil
}

type recordingStore struct {
	values map[string]string
	failOn string
}

func (s *recordingStore) Describe() string { return "test store" }
func (s *recordingStore) Set(_ context.Context, name string, value []byte) error {
	if name == s.failOn {
		return fmt.Errorf("forbidden")
	}
	s.values[name] = string(value)
	return nil
}
func (s *recordingStore) Updated(context.Context) (map[string]time.Time, error) {
	return map[string]time.Time{"PROFILE_DEMO": days(-300)}, nil
}

func manifest() signing.Manifest {
	return signing.Manifest{
		Team:     "TEAM123456",
		Profiles: []signing.ProfileSpec{{Kind: signing.AppStore, Name: signing.MustParseTemplate("{bundleId}")}},
		Targets: []signing.Target{
			{App: "Demo", Environment: "Production", BundleID: "com.example.demo", Secret: "PROFILE_DEMO"},
			{App: "Demo", Environment: "Production", Extension: "share", BundleID: "com.example.demo.share", Secret: "PROFILE_DEMO_SHARE"},
		},
		Cleanup: signing.Scope{Include: []string{"com.example"}},
	}
}

// newIdentity issues a certificate the way Apple would and keeps its identity in a local vault.
func newIdentity(t *testing.T, store vault.Vault, id string, serial int64) identity.Identity {
	t.Helper()
	key, _ := identity.NewKey()
	authority, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Apple Distribution"}, NotBefore: now, NotAfter: days(365)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, authority)
	issued, err := identity.New(der, key)
	if err != nil {
		t.Fatal(err)
	}
	p12, _ := issued.P12("password")
	if err := store.Save(context.Background(), vault.Entry{Team: "TEAM123456", CertificateID: id, P12: p12, Password: "password"}); err != nil {
		t.Fatal(err)
	}
	return issued
}

// profileFile signs a profile property list the way Apple does.
func profileFile(t *testing.T, name, bundleID string, certificates ...[]byte) []byte {
	t.Helper()
	data, _ := plist.Marshal(map[string]any{
		"Name":                  name,
		"TeamIdentifier":        []string{"TEAM123456"},
		"ExpirationDate":        days(365),
		"DeveloperCertificates": certificates,
		"Entitlements":          map[string]any{"application-identifier": "TEAM123456." + bundleID},
	}, plist.XMLFormat)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now, NotAfter: days(365)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	signer, _ := x509.ParseCertificate(der)
	signed, _ := pkcs7.NewSignedData(data)
	if err := signed.AddSigner(signer, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	result, _ := signed.Finish()
	return result
}

func scenario(t *testing.T) (*team, vault.Vault, identity.Identity) {
	store := local.New(t.TempDir())
	issued := newIdentity(t, store, "NEWCERT", 0xAB12)
	portal := &team{
		certificates: []signing.Certificate{{ID: "NEWCERT", Type: signing.CertificateTypeDistribution, SerialNumber: "AB12", ExpiresAt: days(365)}},
		profiles: []signing.Profile{
			{ID: "P1", Name: "com.example.demo", Type: signing.ProfileTypeIOSAppStore, State: signing.ProfileStateActive, BundleID: "com.example.demo", ExpiresAt: days(365), CertificateIDs: []string{"NEWCERT"}},
			{ID: "P2", Name: "com.example.demo.share", Type: signing.ProfileTypeIOSAppStore, State: signing.ProfileStateActive, BundleID: "com.example.demo.share", ExpiresAt: days(365), CertificateIDs: []string{"NEWCERT"}},
		},
		content: map[string][]byte{
			"P1": profileFile(t, "com.example.demo", "com.example.demo", issued.Certificate.Raw),
			"P2": profileFile(t, "com.example.demo.share", "com.example.demo.share", issued.Certificate.Raw),
		},
	}
	return portal, store, issued
}

var names = CertificateSecrets{P12: "CERTIFICATE_BASE64", Password: "CERTIFICATE_PASSWORD"}

func policy() signing.Policy { return signing.Policy{Now: now, ExpiryWindow: 45 * 24 * time.Hour} }

func TestPushWritesTheIdentityAndEveryProfile(t *testing.T) {
	ctx := context.Background()
	portal, store, issued := scenario(t)
	recording := &recordingStore{values: map[string]string{}}
	stores := []secretstore.Store{recording}

	plan, err := Prepare(ctx, portal, []vault.Vault{store}, stores, manifest(), names, policy())
	if err != nil {
		t.Fatal(err)
	}
	var planned []string
	for _, secret := range plan.Secrets {
		planned = append(planned, secret.Name)
	}
	if !slices.Equal(planned, []string{"CERTIFICATE_BASE64", "CERTIFICATE_PASSWORD", "PROFILE_DEMO", "PROFILE_DEMO_SHARE"}) || plan.Fingerprint != issued.Fingerprint() {
		t.Fatalf("planned = %v", planned)
	}
	if plan.Updated["test store"]["PROFILE_DEMO"] != days(-300) {
		t.Fatalf("updated = %v", plan.Updated)
	}

	if formatted := fmt.Sprintf("%v %+v %#v", plan, plan, plan.Secrets); strings.Contains(formatted, "password\"") || strings.Contains(formatted, base64.StdEncoding.EncodeToString(portal.content["P1"])[:40]) {
		t.Fatalf("formatting the plan shows secret values: %s", formatted)
	}

	written, err := Execute(ctx, stores, plan)
	if err != nil || len(written) != 4 {
		t.Fatalf("written = %v, %v", written, err)
	}
	p12, _ := base64.StdEncoding.DecodeString(recording.values["CERTIFICATE_BASE64"])
	if opened, err := identity.Open(p12, recording.values["CERTIFICATE_PASSWORD"]); err != nil || opened.Fingerprint() != issued.Fingerprint() {
		t.Fatalf("pushed identity = %v", err)
	}
	if profile, _ := base64.StdEncoding.DecodeString(recording.values["PROFILE_DEMO_SHARE"]); string(profile) != string(portal.content["P2"]) {
		t.Fatal("pushed profile differs from the downloaded one")
	}
}

func TestPushRefusesProfilesCIcouldNotSignWith(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(*team){
		"com.example.demo.share (P2): does not contain the certificate being pushed": func(portal *team) {
			portal.content["P2"] = profileFile(t, "com.example.demo.share", "com.example.demo.share", []byte("another certificate"))
		},
		"com.example.demo (P1) is signed with another certificate": func(portal *team) {
			portal.profiles[0].CertificateIDs = []string{"OLDCERT"}
		},
		"com.example.demo.share has no live profile": func(portal *team) {
			portal.profiles[1].ExpiresAt = days(-1)
		},
		"P1): is for com.example.other": func(portal *team) {
			portal.content["P1"] = profileFile(t, "com.example.demo", "com.example.other")
		},
	}
	for want, breakIt := range cases {
		portal, store, _ := scenario(t)
		breakIt(portal)
		_, err := Prepare(ctx, portal, []vault.Vault{store}, []secretstore.Store{&recordingStore{values: map[string]string{}}}, manifest(), names, policy())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestPushRefusesAnIdentityForAnotherCertificate(t *testing.T) {
	portal, store, _ := scenario(t)
	portal.certificates[0].SerialNumber = "FFFF"

	_, err := Prepare(context.Background(), portal, []vault.Vault{store}, []secretstore.Store{&recordingStore{}}, manifest(), names, policy())

	if err == nil || !strings.Contains(err.Error(), "serial number is not that certificate's") {
		t.Fatalf("err = %v", err)
	}
}

func TestExecuteStopsAtTheFirstFailure(t *testing.T) {
	portal, store, _ := scenario(t)
	recording := &recordingStore{values: map[string]string{}, failOn: "PROFILE_DEMO"}
	plan, err := Prepare(context.Background(), portal, []vault.Vault{store}, []secretstore.Store{recording}, manifest(), names, policy())
	if err != nil {
		t.Fatal(err)
	}

	written, err := Execute(context.Background(), []secretstore.Store{recording}, plan)

	if err == nil || len(written) != 2 || !strings.Contains(err.Error(), "writing PROFILE_DEMO") {
		t.Fatalf("written = %v, err = %v", written, err)
	}
}
