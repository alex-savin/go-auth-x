package oidcprovider_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// Without a consent screen, only clients the app registered are approved unasked: New refuses the
// configurations that let strangers register, and a self-registered client already in the store
// is turned away rather than silently handed the user's tokens.
func TestNoConsentScreen(t *testing.T) {
	h := setup(t)
	for _, mod := range []func(*oidcprovider.Config){
		func(c *oidcprovider.Config) { c.ConsentURL = nil }, // with setup's Registration
		func(c *oidcprovider.Config) {
			c.ConsentURL, c.Registration, c.ClientMetadataDocuments = nil, false, true
		},
	} {
		cfg := h.cfg
		mod(&cfg)
		if p, err := oidcprovider.New(context.Background(), cfg); err == nil {
			p.Close()
			t.Fatal("New must refuse a nil ConsentURL with Registration or ClientMetadataDocuments")
		}
	}

	h = setup(t, func(c *oidcprovider.Config) { c.ConsentURL, c.Registration = nil, false })
	if _, err := h.p.RegisterClient(authx.OAuthClient{ID: "first-party", RedirectURIs: []string{redirect}, AuthMethod: "none"}); err != nil {
		t.Fatal(err)
	}
	// Registered by itself while registration was on, and still in the store.
	if err := h.store.CreateOAuthClient(&authx.OAuthClient{ID: "dyn_left", RedirectURIs: []string{redirect}, AuthMethod: "none",
		GrantTypes: []string{"authorization_code"}, Dynamic: true, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	loginStep := func(cid string) string {
		_, ch := pkce()
		res := h.get(h.web, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect},
			"state": {"st8"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}.Encode())
		return h.get(h.web, res.Header.Get("Location")).Header.Get("Location")
	}
	if loc := loginStep("first-party"); !strings.Contains(loc, "/oauth/authorize/callback?id=") {
		t.Fatalf("an app-registered client must be approved unasked, got %q", loc)
	}
	if loc := loginStep("dyn_left"); !strings.HasPrefix(loc, redirect) || !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("a self-registered client must be refused without a consent screen, got %q", loc)
	}
}

// A code presented with the wrong PKCE verifier (stolen, say) fails without burning it: single use
// is spent only by an exchange that passes every check.
func TestCodeNotBurnedByFailedExchange(t *testing.T) {
	h := setup(t)
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	next, err := h.p.Approve(context.Background(), h.authorize(cid, nil), h.user.Sub, oidcprovider.Decision{})
	if err != nil {
		t.Fatal(err)
	}
	code := h.code(next)
	if st, _ := h.post("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {cid}, "code_verifier": {strings.Repeat("w", 50)}}); st == 200 {
		t.Fatal("a wrong verifier must not exchange the code")
	}
	if st, tok := h.exchange(cid, code); st != 200 {
		t.Fatalf("the real client's exchange must still work, got %d %v", st, tok)
	}
}

// Two replicas sharing a store exchange a code at most once, even racing: the grant's ID comes from
// the code, so the store refuses the second — and the reuse ends the grant (RFC 6749 §4.1.2).
func TestCodeExchangedOnceAcrossReplicas(t *testing.T) {
	h := setup(t)
	p2, err := oidcprovider.New(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p2.Close)
	mux2 := http.NewServeMux()
	for _, pat := range p2.Patterns() {
		mux2.Handle(pat, p2.Handler())
	}
	srv2 := httptest.NewServer(mux2)
	t.Cleanup(srv2.Close)

	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	next, err := h.p.Approve(context.Background(), h.authorize(cid, nil), h.user.Sub, oidcprovider.Decision{})
	if err != nil {
		t.Fatal(err)
	}
	code := h.code(next)
	verifier, _ := pkce()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "client_id": {cid}, "code_verifier": {verifier}}

	var (
		mu      sync.Mutex
		wins    []string
		wg      sync.WaitGroup
		release = make(chan struct{})
	)
	for i := range 8 {
		base := h.srv.URL
		if i%2 == 1 {
			base = srv2.URL
		}
		wg.Go(func() {
			<-release
			res, err := http.PostForm(base+"/oauth/token", form)
			if err != nil {
				t.Error(err)
				return
			}
			defer res.Body.Close()
			var tok map[string]any
			_ = json.NewDecoder(res.Body).Decode(&tok)
			if res.StatusCode == 200 {
				mu.Lock()
				wins = append(wins, tok["access_token"].(string))
				mu.Unlock()
			}
		})
	}
	close(release)
	wg.Wait()
	if len(wins) != 1 {
		t.Fatalf("the code was exchanged %d times, want exactly once", len(wins))
	}
	if _, err := h.p.Verify(context.Background(), wins[0]); err == nil {
		t.Fatal("the code's reuse must end the grant it made")
	}
}

// A token stops working the moment its grant is revoked or its user may no longer sign in — at
// Verify and at the userinfo endpoint alike, not when it expires.
func TestTokensEndWithGrantAndUser(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	userinfo := func(access string) int {
		req, _ := http.NewRequest("GET", h.srv.URL+"/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}

	access, _ := h.connect(cid, "c1")
	if st := userinfo(access); st != 200 {
		t.Fatalf("userinfo = %d", st)
	}
	if err := h.p.RevokeRef(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if st := userinfo(access); st == 200 {
		t.Fatal("userinfo must refuse a token whose grant was revoked")
	}

	access, _ = h.connect(cid, "c2")
	if _, err := h.p.Verify(ctx, access); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetUserDisabled(h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.Verify(ctx, access); err == nil {
		t.Fatal("a disabled user's access token must stop verifying at once")
	}
	if st := userinfo(access); st == 200 {
		t.Fatal("userinfo must refuse a disabled user's token")
	}
}

// A refresh asking for fewer scopes narrows that access token only: the next refresh may ask for
// the rest again (RFC 6749 §6).
func TestRefreshKeepsGrantedScopes(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	next, err := h.p.Approve(ctx, h.authorize(cid, nil), h.user.Sub, oidcprovider.Decision{})
	if err != nil {
		t.Fatal(err)
	}
	st, tok := h.exchange(cid, h.code(next))
	if st != 200 {
		t.Fatalf("token = %d %v", st, tok)
	}
	refresh := func(rt, scope string) (*oidcprovider.Grant, string) {
		t.Helper()
		st, tok := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {cid}, "scope": {scope}})
		if st != 200 {
			t.Fatalf("refresh = %d %v", st, tok)
		}
		g, err := h.p.Verify(ctx, tok["access_token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return g, tok["refresh_token"].(string)
	}
	g, rt := refresh(tok["refresh_token"].(string), "tree:read")
	if slices.Contains(g.Scopes, "tree:write") {
		t.Fatalf("a narrowed refresh must narrow its access token, got %v", g.Scopes)
	}
	if g, _ = refresh(rt, "tree:read tree:write"); !slices.Contains(g.Scopes, "tree:write") {
		t.Fatalf("a later refresh must get the granted scopes back, got %v", g.Scopes)
	}
}

// Signing keys are sealed at rest. A key stored in the clear (v0.10 and earlier) still signs and is
// sealed in place by the upkeep; a key another CryptoKey sealed is ignored, then deleted once it
// would have expired anyway.
func TestSigningKeysSealed(t *testing.T) {
	// AcceptPlaintextKeys: the upgrade from a version that stored keys unsealed (see
	// TestPlantedPlaintextSigningKeyIsIgnored for the default).
	h := setup(t, func(c *oidcprovider.Config) { c.AcceptPlaintextKeys = true })
	sealed := func(id string) bool {
		t.Helper()
		keys, err := h.store.OAuthSigningKeys()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if k.ID == id {
				return !bytes.Contains(k.PrivatePEM, []byte("PRIVATE KEY"))
			}
		}
		t.Fatalf("key %s is not stored", id)
		return false
	}
	if k := oidcprovider.SigningKeyID(h.p); !sealed(k) {
		t.Fatal("a new signing key must be stored sealed")
	}

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := h.store.AddOAuthSigningKey(&authx.OAuthSigningKey{ID: "legacy", Algorithm: "RS256", PrivatePEM: plain, CreatedAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	if k := oidcprovider.SigningKeyID(h.p); k != "legacy" || !sealed("legacy") {
		t.Fatalf("the plain key must keep signing (got %q) and be sealed in place", k)
	}
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	if tok := h.idToken(cid); keyID(t, tok) != "legacy" || !h.verifies(tok) {
		t.Fatal("ID tokens must be signed with the migrated key and verify")
	}

	cfg2 := h.cfg
	cfg2.CryptoKey = bytes.Repeat([]byte{9}, 32)
	p2, err := oidcprovider.New(context.Background(), cfg2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p2.Close)
	clk := newClock()
	oidcprovider.SetClock(p2, clk.Now)
	if k := oidcprovider.SigningKeyID(p2); k == "legacy" || k == "" {
		t.Fatalf("a replica with another CryptoKey must not use the keys it can't open, got %q", k)
	}
	if err := oidcprovider.MaintainKeys(p2); err != nil {
		t.Fatal(err)
	}
	_ = sealed("legacy") // still stored: young, maybe in use by a replica that can open it
	clk.Add(90*24*time.Hour + 24*time.Hour + time.Hour + time.Minute)
	if err := oidcprovider.MaintainKeys(p2); err != nil {
		t.Fatal(err)
	}
	keys, _ := h.store.OAuthSigningKeys()
	for _, k := range keys {
		if k.ID == "legacy" {
			t.Fatal("an unopenable key past any possible use must be deleted")
		}
	}
}

// New normalizes the resources on its own copy, leaving the caller's slice as given.
func TestConfigResourcesNotMutated(t *testing.T) {
	h := setup(t)
	res := []string{"https://tree.example/mcp/"}
	cfg := h.cfg
	cfg.Resources = res
	p, err := oidcprovider.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if res[0] != "https://tree.example/mcp/" {
		t.Fatalf("the caller's Resources were changed to %q", res[0])
	}
}

// go-auth-x subjects contain a colon ("local:…"), which zitadel's split of a decrypted access token
// ("id:subject") used to reject: userinfo and introspection refused every token, and a client's
// revocation of an access token silently did nothing. All three work now.
func TestAccessTokenEndpointsWithColonSubjects(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	if !strings.Contains(h.user.Sub, ":") {
		t.Fatalf("the test needs a subject with a colon, got %q", h.user.Sub)
	}
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	rs, err := h.p.RegisterClient(authx.OAuthClient{ID: "resource-server", RedirectURIs: []string{"https://rs.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	introspect := func(access string) map[string]any {
		t.Helper()
		req, _ := http.NewRequest("POST", h.srv.URL+"/oauth/introspect", strings.NewReader(url.Values{"token": {access}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("resource-server", rs)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(res.Body).Decode(&m)
		return m
	}

	access, _ := h.connect(cid, "c1")
	req, _ := http.NewRequest("GET", h.srv.URL+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ui map[string]any
	_ = json.NewDecoder(res.Body).Decode(&ui)
	res.Body.Close()
	if res.StatusCode != 200 || ui["sub"] != h.user.Sub {
		t.Fatalf("userinfo = %d %v", res.StatusCode, ui)
	}
	if m := introspect(access); m["active"] != true || m["sub"] != h.user.Sub {
		t.Fatalf("introspection of a live token = %v", m)
	}

	if st, _ := h.post("/oauth/revoke", url.Values{"token": {access}, "token_type_hint": {"access_token"}, "client_id": {cid}}); st != 200 {
		t.Fatalf("revoke = %d", st)
	}
	if _, err := h.p.Verify(ctx, access); err == nil {
		t.Fatal("the client's revocation must end its access token")
	}
	if m := introspect(access); m["active"] == true {
		t.Fatalf("introspection of a revoked token = %v", m)
	}
}
