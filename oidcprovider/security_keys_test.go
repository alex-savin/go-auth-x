package oidcprovider_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// jwksKeyIDs are the key ids the provider publishes.
func (h *harness) jwksKeyIDs() []string {
	h.t.Helper()
	res, err := http.Get(h.srv.URL + "/oauth/keys")
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		h.t.Fatal(err)
	}
	var ids []string
	for _, k := range set.Keys {
		ids = append(ids, k.Kid)
	}
	return ids
}

// A signing key written to the store in the clear is not one the provider signs with or publishes:
// sealing is what ties a stored key to CryptoKey, and a plain PEM was accepted from whoever could
// write the row.
func TestPlantedPlaintextSigningKeyIsIgnored(t *testing.T) {
	h := setup(t)
	own := oidcprovider.SigningKeyID(h.p)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := h.store.AddOAuthSigningKey(&authx.OAuthSigningKey{ID: "planted", Algorithm: "RS256", PrivatePEM: plain, CreatedAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	_ = oidcprovider.MaintainKeys(h.p)
	if k := oidcprovider.SigningKeyID(h.p); k != own {
		t.Fatalf("the provider signs with %q, want its own key %q", k, own)
	}
	for _, id := range h.jwksKeyIDs() {
		if id == "planted" {
			t.Fatal("the planted key is published")
		}
	}
}

// ReplaceKeys leaves one key: after a leak, the old key stops being published at once, where
// RotateKeys keeps it for the grace period.
func TestReplaceKeysDropsTheOldKeyAtOnce(t *testing.T) {
	h := setup(t)
	old := oidcprovider.SigningKeyID(h.p)
	if err := h.p.RotateKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ids := h.jwksKeyIDs(); len(ids) != 2 {
		t.Fatalf("after RotateKeys the old key stays published for the grace: %v", ids)
	}
	if err := h.p.ReplaceKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	ids := h.jwksKeyIDs()
	if len(ids) != 1 || ids[0] == old || ids[0] != oidcprovider.SigningKeyID(h.p) {
		t.Fatalf("after ReplaceKeys only the new key is published: %v (old %s)", ids, old)
	}
}

// Why a client couldn't be looked up is not told to the caller. For a metadata-document client the
// reason names what a hostname of the caller's choosing resolves to.
func TestClientLookupFailureSaysNothing(t *testing.T) {
	h := setup(t, func(c *oidcprovider.Config) { c.ClientMetadataDocuments = true })
	for _, id := range []string{"https://localhost/internal.json", "https://127.0.0.1:1/x.json", "no-such-client"} {
		res, err := http.PostForm(h.srv.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {id}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		for _, leak := range []string{"resolves", "not public", "127.0.0.1", "::1", "localhost", "refused", "not found"} {
			if strings.Contains(string(body), leak) {
				t.Fatalf("client_id %q: the answer says %q: %s", id, leak, body)
			}
		}
		if res.StatusCode >= 500 {
			t.Fatalf("client_id %q = %d %s, want a client error", id, res.StatusCode, body)
		}
	}
}

// An authorization request is bounded before it is stored: its parameters' sizes, and how many one
// address may start.
func TestAuthorizationRequestsAreBounded(t *testing.T) {
	h := setup(t)
	cid := h.publicClient()
	_, ch := pkce()
	start := func(state string) int {
		res := h.get(browser(), "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect},
			"state": {state}, "code_challenge": {ch}, "code_challenge_method": {"S256"}, "resource": {h.srv.URL + "/mcp"}}.Encode())
		return res.StatusCode
	}
	if code := start(strings.Repeat("s", 3000)); code != http.StatusBadRequest {
		t.Fatalf("a 3 KB state = %d, want 400", code)
	}
	res, err := http.PostForm(h.srv.URL+"/oauth/authorize", url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect},
		"state": {strings.Repeat("s", 1<<20)}, "code_challenge": {ch}, "code_challenge_method": {"S256"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a 1 MiB POST = %d, want 400", res.StatusCode)
	}
	limited := false
	for i := 0; i < 200 && !limited; i++ {
		limited = start("ok") == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("200 requests from one address were all accepted")
	}
}

// /revoke takes bearer values. What the store holds — a refresh token's hash, an access token's row
// id — revokes nothing: stored values must be useless to whoever reads the database.
func TestRevokeIgnoresStoredKeys(t *testing.T) {
	h := setup(t)
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	access, refresh := h.connect(cid, "ref")
	for _, tok := range []string{"rt:" + oidcprovider.HashForTest(refresh), "rt:" + refresh} {
		for _, hint := range []string{"", "access_token", "refresh_token"} {
			h.post("/oauth/revoke", url.Values{"token": {tok}, "token_type_hint": {hint}, "client_id": {cid}})
		}
	}
	if _, err := h.p.Verify(context.Background(), access); err != nil {
		t.Fatalf("a stored key revoked the grant: %v", err)
	}
	// The bearer value still revokes.
	h.post("/oauth/revoke", url.Values{"token": {refresh}, "client_id": {cid}})
	if _, err := h.p.Verify(context.Background(), access); err == nil {
		t.Fatal("revoking the refresh token must end the grant")
	}
}

// The metadata advertises what the provider does: no logout endpoint that ends nothing, no
// client-assertion algorithms it refuses.
func TestDiscoveryAdvertisesOnlyWhatWorks(t *testing.T) {
	h := setup(t)
	res, err := http.Get(h.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"end_session_endpoint", "device_authorization_endpoint", "token_endpoint_auth_signing_alg_values_supported",
		"revocation_endpoint_auth_signing_alg_values_supported", "introspection_endpoint_auth_signing_alg_values_supported", "claims_supported"} {
		if _, ok := doc[k]; ok {
			t.Errorf("the metadata advertises %s", k)
		}
	}
	for _, k := range []string{"token_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported", "introspection_endpoint_auth_methods_supported"} {
		if v, ok := doc[k]; ok && strings.Contains(strings.ToLower(strings.Join(strings.Fields(strings.Trim(jsonString(v), "[]")), "")), "jwt") {
			t.Errorf("%s advertises a JWT client assertion: %v", k, v)
		}
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"} {
		if doc[k] == nil {
			t.Errorf("the metadata lacks %s", k)
		}
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// A client's self-declared name and links reach the consent page without markup characters.
func TestClientMetadataCarriesNoMarkup(t *testing.T) {
	h := setup(t)
	code, m := h.register(map[string]any{
		"redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none",
		"client_name": `<img src=x onerror=alert(1)>"Assistant"`,
		"client_uri":  `https://evil.example/?'onmouseover='alert(1)`,
		"logo_uri":    `https://evil.example/l.png?"><script>alert(1)</script>`,
	})
	if code != http.StatusCreated {
		t.Fatalf("register = %d %v", code, m)
	}
	c, err := h.store.OAuthClient(m["client_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(c.Name+c.URI+c.LogoURI, "<>\"'`") {
		t.Fatalf("stored client metadata carries markup: name=%q uri=%q logo=%q", c.Name, c.URI, c.LogoURI)
	}
	if c.Name == "" {
		t.Fatal("the name's text should survive")
	}
}
