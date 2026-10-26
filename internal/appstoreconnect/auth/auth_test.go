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
	"math/big"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestTokenIsAVerifiableES256JWT(t *testing.T) {
	private, pemData := testKey(t)
	key, err := ParseKey("KEY1234567", "issuer", pemData)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)

	token, err := NewTokenSource(key, func() time.Time { return now }).Token()
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	var header map[string]string
	var claims map[string]any
	decodeJSON(t, parts[0], &header)
	decodeJSON(t, parts[1], &claims)
	if header["alg"] != "ES256" || header["kid"] != "KEY1234567" {
		t.Fatalf("header = %v", header)
	}
	if claims["iss"] != "issuer" || claims["aud"] != "appstoreconnect-v1" || claims["exp"].(float64)-claims["iat"].(float64) != 1140 {
		t.Fatalf("claims = %v", claims)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature length = %d, %v", len(signature), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&private.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("signature does not verify")
	}
}

func TestTokenIsReusedUntilShortlyBeforeExpiry(t *testing.T) {
	_, pemData := testKey(t)
	key, _ := ParseKey("KEY1234567", "issuer", pemData)
	now := time.Unix(1_800_000_000, 0)
	source := NewTokenSource(key, func() time.Time { return now })

	first, _ := source.Token()
	now = now.Add(17 * time.Minute)
	second, _ := source.Token()
	now = now.Add(90 * time.Second)
	third, _ := source.Token()

	if first != second {
		t.Fatal("token was not reused")
	}
	if third == second {
		t.Fatal("token was reused within a minute of expiry")
	}
}

func TestParseKeyRejectsOtherKeys(t *testing.T) {
	if _, err := ParseKey("K", "I", []byte("not pem")); err == nil {
		t.Fatal("accepted non-PEM data")
	}
	private, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	if _, err := ParseKey("K", "I", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("accepted a P-384 key")
	}
}

func decodeJSON(t *testing.T, segment string, target any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
