package authx_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// fakeIdP is an OIDC provider whose next id_token carries the claims a test sets.
type fakeIdP struct {
	srv *httptest.Server
	mu  sync.Mutex
	// claims for the next token (iss, aud, nonce, iat, exp are filled in)
	next jwt.MapClaims
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	iss := p.srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		claims := jwt.MapClaims{}
		maps.Copy(claims, p.next)
		p.mu.Unlock()
		claims["iss"], claims["aud"] = iss, "app-client"
		claims["iat"], claims["exp"] = time.Now().Unix(), time.Now().Add(time.Hour).Unix()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k1"
		raw, _ := tok.SignedString(key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
	})
	return p
}

// newOIDCTestAuth is newTestAuth with the primary OIDC client pointed at idp.
func newOIDCTestAuth(t *testing.T, idp *fakeIdP, assumeVerified bool) (*authx.Authenticator, *memory.Store) {
	t.Helper()
	store := memory.New()
	a, err := authx.New(context.Background(), authx.Config{
		SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", OwnerEmail: "owner@example.com",
		Issuer: idp.srv.URL, ClientID: "app-client", ClientSecret: "s", RedirectURL: "https://app.example.com/auth/callback",
		OIDCAssumeVerified: assumeVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(store)
	a.SetDirectoryStore(store)
	a.SetTwoFactorStore(store)
	a.SetSessionStore(store)
	a.SetOrgStore(store)
	a.SetMailer(&capMailer{})
	a.SetAuthorizer(store.Authorizer())
	a.SetLocalEnabled(true)
	return a, store
}

// oidcSignIn runs /auth/login → /auth/callback with an id_token carrying claims, returning the
// callback's response.
func (p *fakeIdP) oidcSignIn(t *testing.T, c *client, claims jwt.MapClaims) *httptest.ResponseRecorder {
	t.Helper()
	w := c.do("GET", "/auth/login", nil)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusFound {
		t.Fatalf("login = %d %q", w.Code, w.Header().Get("Location"))
	}
	q := loc.Query()
	p.mu.Lock()
	p.next = jwt.MapClaims{"nonce": q.Get("nonce")}
	maps.Copy(p.next, claims)
	p.mu.Unlock()
	return c.do("GET", "/auth/callback?code=c&state="+url.QueryEscape(q.Get("state")), nil)
}
