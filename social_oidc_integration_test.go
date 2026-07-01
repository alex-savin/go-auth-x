package authx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// mockIDP stands up a minimal OIDC issuer (discovery document + JWKS) and signs id_tokens, so the
// generic-OIDC social path (oidcSocialIdentity) can be exercised end-to-end against a real
// go-oidc verifier — JWKS fetch, RS256 signature check, and claim extraction included.
type mockIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIDP{key: key, kid: "test-key"}
	mux := http.NewServeMux()
	m.server = httptest.NewServer(mux)
	issuer := m.server.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockIDP) idToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iss"] = m.server.URL
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.kid
	s, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (m *mockIDP) verifier(t *testing.T, clientID string) *oidc.IDTokenVerifier {
	t.Helper()
	p, err := oidc.NewProvider(context.Background(), m.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return p.Verifier(&oidc.Config{ClientID: clientID})
}

func tokenWithID(raw string) *oauth2.Token {
	return (&oauth2.Token{AccessToken: "x", Expiry: time.Now().Add(time.Hour)}).
		WithExtra(map[string]any{"id_token": raw})
}

func TestOIDCSocialIdentityIntegration(t *testing.T) {
	idp := newMockIDP(t)
	ver := idp.verifier(t, "client-1")
	ctx := context.Background()
	const nonce = "n-123"

	// Happy path: a verified email is accepted; claims come back intact.
	raw := idp.idToken(t, jwt.MapClaims{
		"aud": "client-1", "sub": "user-1", "nonce": nonce,
		"email": "a@x.com", "email_verified": true, "name": "Alice",
	})
	sub, email, name, err := oidcSocialIdentity(ctx, ver, "client-1", tokenWithID(raw), nonce, false)
	if err != nil {
		t.Fatalf("verified path: %v", err)
	}
	if sub != "user-1" || email != "a@x.com" || name != "Alice" {
		t.Fatalf("identity wrong: %q / %q / %q", sub, email, name)
	}

	// Unverified email, strict (assumeVerified=false) → refused.
	raw = idp.idToken(t, jwt.MapClaims{"aud": "client-1", "sub": "u2", "nonce": nonce, "email": "b@x.com", "email_verified": false})
	if _, _, _, err := oidcSocialIdentity(ctx, ver, "client-1", tokenWithID(raw), nonce, false); err == nil {
		t.Fatal("unverified+strict: want error, got nil")
	}

	// email_verified absent + assumeVerified → the token email is trusted.
	raw = idp.idToken(t, jwt.MapClaims{"aud": "client-1", "sub": "u3", "nonce": nonce, "email": "c@x.com"})
	sub, email, _, err = oidcSocialIdentity(ctx, ver, "client-1", tokenWithID(raw), nonce, true)
	if err != nil || sub != "u3" || email != "c@x.com" {
		t.Fatalf("assumeVerified path: err=%v sub=%q email=%q", err, sub, email)
	}

	// Entra-style: no email claim, an email-shaped preferred_username, assumeVerified → UPN used.
	raw = idp.idToken(t, jwt.MapClaims{"aud": "client-1", "sub": "u4", "nonce": nonce, "preferred_username": "d@corp.com"})
	_, email, name, err = oidcSocialIdentity(ctx, ver, "client-1", tokenWithID(raw), nonce, true)
	if err != nil || email != "d@corp.com" || name != "d@corp.com" {
		t.Fatalf("entra upn path: err=%v email=%q name=%q", err, email, name)
	}

	// Nonce mismatch → refused (replay of a token minted for a different login attempt).
	raw = idp.idToken(t, jwt.MapClaims{"aud": "client-1", "sub": "u5", "nonce": "wrong", "email": "e@x.com", "email_verified": true})
	if _, _, _, err := oidcSocialIdentity(ctx, ver, "client-1", tokenWithID(raw), nonce, false); err == nil {
		t.Fatal("nonce mismatch: want error, got nil")
	}

	// azp names a different client → refused (token not authorized for us).
	raw = idp.idToken(t, jwt.MapClaims{"aud": "client-1", "azp": "attacker", "sub": "u6", "nonce": nonce, "email": "f@x.com", "email_verified": true})
	if _, _, _, err := oidcSocialIdentity(ctx, ver, "client-1", tokenWithID(raw), nonce, false); err == nil {
		t.Fatal("azp mismatch: want error, got nil")
	}

	// A token signed by a DIFFERENT issuer key → signature verification fails.
	other := newMockIDP(t)
	raw = other.idToken(t, jwt.MapClaims{"aud": "client-1", "sub": "u7", "nonce": nonce, "email": "g@x.com", "email_verified": true})
	if _, _, _, err := oidcSocialIdentity(ctx, ver, "client-1", tokenWithID(raw), nonce, false); err == nil {
		t.Fatal("foreign signature: want error, got nil")
	}
}
