package oidcprovider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/oidcprovider"
	"github.com/alex-savin/go-auth-x/store/memory"
)

const redirect = "http://127.0.0.1:9999/cb"

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	p     *oidcprovider.Provider
	cfg   oidcprovider.Config // p's configuration, for a second replica
	store *memory.Store
	user  *authx.AuthUser
	web   *http.Client // a browser: cookies, no redirects followed
}

// setup serves an Authenticator and a provider; opts adjust the provider's configuration.
func setup(t *testing.T, opts ...func(*oidcprovider.Config)) *harness {
	t.Helper()
	h := &harness{t: t, store: memory.New()}
	mux := http.NewServeMux()
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)

	a, err := authx.New(context.Background(), authx.Config{SessionSecret: []byte("0123456789abcdef0123456789abcdef"), AppURL: h.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(h.store)
	a.SetDirectoryStore(h.store)
	a.SetSessionStore(h.store)
	a.SetAuthorizer(h.store.Authorizer())
	a.SetLocalEnabled(true)

	h.cfg = oidcprovider.Config{
		Issuer: h.srv.URL, Auth: a, Store: h.store, CryptoKey: bytes.Repeat([]byte{7}, 32),
		Scopes: []string{"tree:read", "tree:write"}, DefaultScopes: []string{"tree:read", "tree:write"},
		Resources:    []string{h.srv.URL + "/mcp"},
		ConsentURL:   func(id string) string { return "/consent?id=" + id },
		Registration: true, Insecure: true,
	}
	for _, o := range opts {
		o(&h.cfg)
	}
	h.p, err = oidcprovider.New(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.p.Close)
	mux.Handle("/auth/", a.Handler())
	for _, pat := range h.p.Patterns() {
		mux.Handle(pat, h.p.Handler())
	}

	h.user = h.seed("u@x.com", "correct horse battery staple")
	jar, _ := cookiejar.New(nil)
	h.web = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}

func (h *harness) seed(email, pw string) *authx.AuthUser {
	u, err := h.store.CreateLocalUser(email, "Name")
	if err != nil {
		h.t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	_ = h.store.SetPasswordHash(u.ID, string(hash), "bcrypt")
	_ = h.store.SetEmailVerified(u.ID, true)
	return u
}

func (h *harness) signIn(c *http.Client, email, pw string) {
	h.t.Helper()
	b, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	req, _ := http.NewRequest("POST", h.srv.URL+"/auth/password/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.srv.URL)
	res, err := c.Do(req)
	if err != nil || res.StatusCode != 200 {
		h.t.Fatalf("sign in: %v %v", err, res.Status)
	}
	res.Body.Close()
}

func (h *harness) get(c *http.Client, path string) *http.Response {
	h.t.Helper()
	if !strings.HasPrefix(path, "http") {
		path = h.srv.URL + path
	}
	res, err := c.Get(path)
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func (h *harness) post(path string, form url.Values) (int, map[string]any) {
	h.t.Helper()
	res, err := http.PostForm(h.srv.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	return res.StatusCode, m
}

func (h *harness) register(meta map[string]any) (int, map[string]any) {
	h.t.Helper()
	b, _ := json.Marshal(meta)
	res, err := http.Post(h.srv.URL+"/oauth/register", "application/json", bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	return res.StatusCode, m
}

func (h *harness) publicClient() string {
	code, m := h.register(map[string]any{"redirect_uris": []string{redirect}, "client_name": "Assistant", "grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none"})
	if code != 201 || m["client_id"] == nil || m["client_secret"] != nil {
		h.t.Fatalf("register = %d %v", code, m)
	}
	return m["client_id"].(string)
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 50)
	s := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(s[:])
}

// authorize runs /authorize and the login step and returns the request id waiting for consent.
func (h *harness) authorize(clientID string, extra url.Values) string {
	h.t.Helper()
	_, ch := pkce()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"st8"},
		"code_challenge": {ch}, "code_challenge_method": {"S256"}, "resource": {h.srv.URL + "/mcp"}}
	for k, v := range extra {
		q[k] = v
	}
	res := h.get(h.web, "/oauth/authorize?"+q.Encode())
	loc := res.Header.Get("Location")
	if res.StatusCode != 302 || !strings.Contains(loc, "/oauth/login?id=") {
		h.t.Fatalf("authorize = %d %q", res.StatusCode, loc)
	}
	res = h.get(h.web, loc)
	loc = res.Header.Get("Location")
	if res.StatusCode != 302 || !strings.HasPrefix(loc, "/consent?id=") {
		h.t.Fatalf("login step = %d %q", res.StatusCode, loc)
	}
	return strings.TrimPrefix(loc, "/consent?id=")
}

// code follows the approval's callback to the client's redirect and returns the code.
func (h *harness) code(next string) string {
	h.t.Helper()
	res := h.get(h.web, next)
	u, err := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || err != nil || !strings.HasPrefix(u.String(), redirect) || u.Query().Get("state") != "st8" || u.Query().Get("code") == "" {
		h.t.Fatalf("callback = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	return u.Query().Get("code")
}

func (h *harness) exchange(clientID, code string) (int, map[string]any) {
	v, _ := pkce()
	return h.post("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {v}})
}

func (h *harness) connect(clientID, ref string) (access, refresh string) {
	h.t.Helper()
	id := h.authorize(clientID, nil)
	next, err := h.p.Approve(context.Background(), id, h.user.Sub, oidcprovider.Decision{Scopes: []string{"tree:read"}, Ref: ref})
	if err != nil {
		h.t.Fatal(err)
	}
	st, tok := h.exchange(clientID, h.code(next))
	if st != 200 {
		h.t.Fatalf("token = %d %v", st, tok)
	}
	return tok["access_token"].(string), tok["refresh_token"].(string)
}

func TestFlow(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	// Metadata, as MCP clients read it.
	res, err := http.Get(h.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	_ = json.NewDecoder(res.Body).Decode(&meta)
	res.Body.Close()
	for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri", "revocation_endpoint"} {
		if s, _ := meta[k].(string); !strings.HasPrefix(s, h.srv.URL) {
			t.Errorf("metadata %s = %v", k, meta[k])
		}
	}
	if ms, _ := meta["code_challenge_methods_supported"].([]any); len(ms) != 1 || ms[0] != "S256" {
		t.Errorf("code challenge methods = %v", meta["code_challenge_methods_supported"])
	}

	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")

	// The consent screen sees the request (scopes defaulted, resource bound); nobody else does.
	id := h.authorize(cid, nil)
	req, err := h.p.Pending(ctx, id, h.user.Sub)
	if err != nil {
		t.Fatal(err)
	}
	if req.Client.Name != "Assistant" || !req.Client.Dynamic || req.Client.RedirectHost != "127.0.0.1:9999" ||
		!slices.Contains(req.Scopes, "tree:write") || !slices.Equal(req.Resources, []string{h.srv.URL + "/mcp"}) {
		t.Fatalf("pending = %+v", req)
	}
	if _, err := h.p.Pending(ctx, id, "local:someone-else"); !errors.Is(err, oidcprovider.ErrNoRequest) {
		t.Fatalf("another user's pending = %v", err)
	}
	if _, err := h.p.Approve(ctx, id, "local:someone-else", oidcprovider.Decision{}); !errors.Is(err, oidcprovider.ErrNoRequest) {
		t.Fatalf("another user's approval = %v", err)
	}

	// Approved with less than asked: the token carries only that, and the app's reference.
	next, err := h.p.Approve(ctx, id, h.user.Sub, oidcprovider.Decision{Scopes: []string{"tree:read"}, Ref: "conn-1"})
	if err != nil {
		t.Fatal(err)
	}
	code := h.code(next)
	st, tok := h.exchange(cid, code)
	if st != 200 || tok["access_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token = %d %v", st, tok)
	}
	access, refresh := tok["access_token"].(string), tok["refresh_token"].(string)
	g, err := h.p.VerifyFor(ctx, access, h.srv.URL+"/mcp/")
	if err != nil {
		t.Fatal(err)
	}
	if g.Ref != "conn-1" || g.Subject != h.user.Sub || g.ClientName != "Assistant" || !slices.Contains(g.Scopes, "tree:read") || slices.Contains(g.Scopes, "tree:write") {
		t.Fatalf("grant = %+v", g)
	}
	if _, err := h.p.VerifyFor(ctx, access, "https://elsewhere.example/mcp"); err == nil {
		t.Fatal("a token for another resource must not verify")
	}
	if _, err := h.p.Verify(ctx, access+"x"); err == nil {
		t.Fatal("a tampered token must not verify")
	}

	// A code is used once.
	if st, _ := h.exchange(cid, code); st == 200 {
		t.Fatal("a code must not be exchanged twice")
	}

	// Refreshing rotates; replaying the old refresh token ends the grant.
	st, tok = h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {cid}})
	if st != 200 || tok["refresh_token"] == refresh {
		t.Fatalf("refresh = %d %v", st, tok)
	}
	access2 := tok["access_token"].(string)
	if _, err := h.p.Verify(ctx, access2); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {cid}}); st == 200 {
		t.Fatal("a used refresh token must not work again")
	}
	if _, err := h.p.Verify(ctx, access2); err == nil {
		t.Fatal("replaying a refresh token must end the grant")
	}

	// The app revoking its connection ends the tokens.
	access3, _ := h.connect(cid, "conn-2")
	if _, err := h.p.Verify(ctx, access3); err != nil {
		t.Fatal(err)
	}
	if err := h.p.RevokeRef(ctx, "conn-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.Verify(ctx, access3); err == nil {
		t.Fatal("a revoked connection's token must not verify")
	}

	// The client revoking its refresh token ends the grant too.
	access4, refresh4 := h.connect(cid, "conn-3")
	if st, _ := h.post("/oauth/revoke", url.Values{"token": {refresh4}, "token_type_hint": {"refresh_token"}, "client_id": {cid}}); st != 200 {
		t.Fatalf("revoke = %d", st)
	}
	if _, err := h.p.Verify(ctx, access4); err == nil {
		t.Fatal("revoking the refresh token must end the grant")
	}
}

func TestDenyAndRefusals(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	cid := h.publicClient()

	// Signed out: the login step sends the browser to sign in and back.
	_, ch := pkce()
	q := url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect}, "state": {"st8"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}
	res := h.get(h.web, "/oauth/authorize?"+q.Encode())
	res = h.get(h.web, res.Header.Get("Location"))
	if loc := res.Header.Get("Location"); res.StatusCode != 302 || !strings.HasPrefix(loc, "/welcome?next=") || !strings.Contains(loc, url.QueryEscape("/oauth/login?id=")) {
		t.Fatalf("signed-out login step = %d %q", res.StatusCode, loc)
	}

	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	id := h.authorize(cid, nil)
	to, err := h.p.Deny(ctx, id, h.user.Sub)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	if !strings.HasPrefix(to, redirect) || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "st8" || u.Query().Get("iss") != h.srv.URL {
		t.Fatalf("deny = %q", to)
	}
	if _, err := h.p.Approve(ctx, id, h.user.Sub, oidcprovider.Decision{}); err == nil {
		t.Fatal("a denied request must not be approved afterwards")
	}

	// A resource not served here.
	res = h.get(h.web, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect},
		"code_challenge": {ch}, "code_challenge_method": {"S256"}, "resource": {"https://evil.example/mcp"}}.Encode())
	if res.StatusCode != 400 {
		t.Fatalf("foreign resource = %d", res.StatusCode)
	}

	// A public client without PKCE.
	res = h.get(h.web, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect}, "state": {"s"}}.Encode())
	if loc := res.Header.Get("Location"); strings.Contains(loc, "/oauth/login") {
		t.Fatalf("no PKCE must be refused, got %d %q", res.StatusCode, loc)
	}

	// A redirect not registered.
	res = h.get(h.web, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {"https://evil.example/cb"},
		"code_challenge": {ch}, "code_challenge_method": {"S256"}}.Encode())
	if loc := res.Header.Get("Location"); strings.HasPrefix(loc, "https://evil.example") || strings.Contains(loc, "/oauth/login") {
		t.Fatalf("unregistered redirect = %d %q", res.StatusCode, loc)
	}

	// Registration refuses dangerous redirects and unknown methods.
	for _, m := range []map[string]any{
		{"redirect_uris": []string{"javascript:alert(1)"}},
		{"redirect_uris": []string{"http://evil.example/cb"}},
		{"redirect_uris": []string{"https://ok.example/cb#frag"}},
		{"redirect_uris": []string{}},
		{"redirect_uris": []string{"https://ok.example/cb"}, "grant_types": []string{"client_credentials"}},
		{"redirect_uris": []string{"https://ok.example/cb"}, "token_endpoint_auth_method": "private_key_jwt"},
	} {
		if code, _ := h.register(m); code != 400 {
			t.Errorf("register %v = %d, want 400", m, code)
		}
	}

	// A confidential client gets a secret and must use it.
	code, m := h.register(map[string]any{"redirect_uris": []string{"https://ok.example/cb"}, "client_name": "Web‮app\x07"})
	if code != 201 || m["client_secret"] == nil || m["client_name"] != "Webapp" {
		t.Fatalf("confidential register = %d %v", code, m)
	}
}

func TestDisabledUserGetsNoTokens(t *testing.T) {
	h := setup(t)
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	_, refresh := h.connect(cid, "c")
	if err := h.store.SetUserDisabled(h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {cid}}); st == 200 {
		t.Fatal("a disabled user's refresh must fail")
	}
}
