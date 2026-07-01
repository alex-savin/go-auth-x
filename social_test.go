package authx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func testApplePEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), key
}

func TestParseApplePrivateKey(t *testing.T) {
	pemStr, _ := testApplePEM(t)
	if _, err := parseApplePrivateKey(pemStr); err != nil {
		t.Fatalf("parse P-256 PKCS8: %v", err)
	}
	if _, err := parseApplePrivateKey(strings.ReplaceAll(pemStr, "\n", "\\n")); err != nil {
		t.Fatalf("parse \\n-escaped (env-var style) key: %v", err)
	}
	if _, err := parseApplePrivateKey("not a pem"); err == nil {
		t.Fatal("expected an error for junk input")
	}
}

func TestAppleClientSecret(t *testing.T) {
	_, key := testApplePEM(t)
	a := &Authenticator{
		cfg:      Config{AppleTeamID: "TEAM123", AppleClientID: "com.example.svc", AppleKeyID: "KEY123"},
		appleKey: key,
	}
	secret, err := a.appleClientSecret()
	if err != nil {
		t.Fatalf("appleClientSecret: %v", err)
	}
	tok, err := jwt.Parse(secret, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, errors.New("not ES256")
		}
		return &key.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		t.Fatalf("client secret should verify with the key: %v", err)
	}
	if tok.Header["kid"] != "KEY123" || tok.Header["alg"] != "ES256" {
		t.Fatalf("header wrong: %v", tok.Header)
	}
	cl := tok.Claims.(jwt.MapClaims)
	if cl["iss"] != "TEAM123" || cl["sub"] != "com.example.svc" {
		t.Fatalf("iss/sub wrong: %v", cl)
	}
	if aud, _ := cl.GetAudience(); len(aud) == 0 || aud[0] != appleIssuer {
		t.Fatalf("aud wrong: %v", aud)
	}
}

func TestExchangeConfig(t *testing.T) {
	_, key := testApplePEM(t)
	a := &Authenticator{cfg: Config{AppleTeamID: "T", AppleClientID: "C", AppleKeyID: "K"}, appleKey: key}
	// Apple → a COPY with a freshly signed secret; the shared base is untouched.
	base := &oauth2.Config{ClientID: "C"}
	ac, err := a.exchangeConfig("apple", base)
	if err != nil || ac == base || ac.ClientSecret == "" {
		t.Fatalf("apple exchange: err=%v same=%v secret=%q", err, ac == base, ac.ClientSecret)
	}
	if base.ClientSecret != "" {
		t.Fatal("exchangeConfig must not mutate the shared base config")
	}
	// Others → passthrough unchanged.
	gh := &oauth2.Config{ClientID: "gh"}
	if oc, err := a.exchangeConfig("github", gh); err != nil || oc != gh {
		t.Fatalf("github should pass through unchanged: %v", err)
	}
}

func TestAppleNameFromUser(t *testing.T) {
	if n := appleNameFromUser(`{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"a@b.com"}`); n != "Ada Lovelace" {
		t.Fatalf("name = %q, want 'Ada Lovelace'", n)
	}
	for _, junk := range []string{"", "garbage", "{}"} {
		if n := appleNameFromUser(junk); n != "" {
			t.Fatalf("%q → want empty name, got %q", junk, n)
		}
	}
}

func TestHMACSHA256Hex(t *testing.T) {
	// Standard HMAC-SHA256 test vector (used for Facebook's appsecret_proof).
	got := hmacSHA256Hex("key", "The quick brown fox jumps over the lazy dog")
	want := "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	if got != want {
		t.Fatalf("hmac = %s, want %s", got, want)
	}
}
