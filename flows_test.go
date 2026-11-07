package authx_test

// End-to-end coverage for flows that had none: magic-link sign-in, the admin REST API's group /
// API-key / disable verbs, changing a password, logout, and reading the configuration from env.

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

func TestMagicLinkSignIn(t *testing.T) {
	a, s, m := newTestAuth(t)
	seedUser(t, s, "magic@x.com", "", true)
	c := newClient(t, a)

	if w := c.do("POST", "/auth/email/request", map[string]any{"email": "magic@x.com"}); w.Code != 200 {
		t.Fatalf("request = %d %s", w.Code, w.Body.String())
	}
	token := tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/login").text)[1]

	w := c.do("GET", "/auth/email/login?token="+token, nil)
	if w.Code != http.StatusFound || c.cookies["sweep_session"] == "" {
		t.Fatalf("redeem = %d %q, cookies %v", w.Code, w.Header().Get("Location"), c.cookies)
	}
	if me := decode(t, c.do("GET", "/auth/me", nil)); me["email"] != "magic@x.com" {
		t.Fatalf("/auth/me after a magic link = %v", me)
	}

	// Single use: the same link again signs no one in.
	other := newClient(t, a)
	if w := other.do("GET", "/auth/email/login?token="+token, nil); other.cookies["sweep_session"] != "" ||
		!strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatalf("a used link must not sign in again: %d %q", w.Code, w.Header().Get("Location"))
	}

	// An unknown address gets the same answer, and no email (no account enumeration).
	m.mu.Lock()
	before := len(m.msgs)
	m.mu.Unlock()
	if w := c.do("POST", "/auth/email/request", map[string]any{"email": "nobody@x.com"}); w.Code != 200 {
		t.Fatalf("unknown-address request = %d", w.Code)
	}
	time.Sleep(100 * time.Millisecond)
	m.mu.Lock()
	n := len(m.msgs)
	m.mu.Unlock()
	if n != before {
		t.Fatal("an unknown address must not be sent an email")
	}
}

// adminCall sends a Bearer-authenticated admin API request.
func adminCall(t *testing.T, a *authx.Authenticator, key, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func TestAdminAPI_GroupsKeysAndDisable(t *testing.T) {
	a, s, _ := newTestAuth(t)
	u := seedUser(t, s, "member@x.com", "hunter2hunter2", true)
	mint := func(raw string, scopes ...string) {
		h := sha256.Sum256([]byte(raw))
		if _, err := s.CreateAPIKey(raw, nil, scopes, raw[:8], h[:], nil); err != nil {
			t.Fatal(err)
		}
	}
	mint("axk_admin_key", "admin")
	mint("axk_scim_key", "scim")
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		return adminCall(t, a, "axk_admin_key", method, path, body)
	}

	// A key without the admin scope is refused; no key at all is unauthenticated.
	if w := adminCall(t, a, "axk_scim_key", "GET", "/auth/admin/groups", nil); w.Code != http.StatusForbidden {
		t.Fatalf("a scim-scoped key = %d, want 403", w.Code)
	}
	if w := adminCall(t, a, "axk_nope", "GET", "/auth/admin/groups", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown key = %d, want 401", w.Code)
	}

	// Groups: create (a duplicate is a conflict), add a member, list, remove, delete.
	w := call("POST", "/auth/admin/groups", map[string]any{"name": "analysts", "description": "d"})
	var g authx.Group
	if json.Unmarshal(w.Body.Bytes(), &g); w.Code != 200 || g.ID == "" {
		t.Fatalf("create group = %d %s", w.Code, w.Body.String())
	}
	if w := call("POST", "/auth/admin/groups", map[string]any{"name": "analysts"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate group = %d, want 409", w.Code)
	}
	if w := call("POST", "/auth/admin/groups/"+g.ID+"/members/"+u.ID, nil); w.Code != 200 {
		t.Fatalf("add member = %d %s", w.Code, w.Body.String())
	}
	if w := call("GET", "/auth/admin/groups/"+g.ID+"/members", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "member@x.com") {
		t.Fatalf("members = %d %s", w.Code, w.Body.String())
	}
	if w := call("GET", "/auth/admin/groups", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"analysts"`) {
		t.Fatalf("list groups = %d %s", w.Code, w.Body.String())
	}
	if w := call("DELETE", "/auth/admin/groups/"+g.ID+"/members/"+u.ID, nil); w.Code != 200 {
		t.Fatalf("remove member = %d", w.Code)
	}
	if gs, _ := s.UserGroups(u.ID); len(gs) != 0 {
		t.Fatalf("the member must be removed, still in %v", gs)
	}
	if w := call("DELETE", "/auth/admin/groups/"+g.ID, nil); w.Code != 200 {
		t.Fatalf("delete group = %d", w.Code)
	}
	if _, err := s.GroupByName("analysts"); err == nil {
		t.Fatal("the group must be deleted")
	}

	// Disabling a user stops their sign-in; enabling restores it.
	if w := call("POST", "/auth/admin/users/"+u.ID+"/disabled", map[string]any{"disabled": true}); w.Code != 200 {
		t.Fatalf("disable = %d %s", w.Code, w.Body.String())
	}
	if w := newClient(t, a).do("POST", "/auth/password/login", map[string]any{"email": "member@x.com", "password": "hunter2hunter2"}); w.Code == 200 {
		t.Fatal("a disabled user must not sign in")
	}
	if w := call("POST", "/auth/admin/users/"+u.ID+"/disabled", map[string]any{"disabled": false}); w.Code != 200 {
		t.Fatalf("enable = %d", w.Code)
	}
	newClient(t, a).login("member@x.com", "hunter2hunter2")

	// API keys: create (the raw key once), list (never the key), use, revoke.
	w = call("POST", "/auth/admin/apikeys", map[string]any{"name": "ci", "scopes": []string{"scim"}})
	var created struct {
		Key    string           `json:"key"`
		APIKey authx.APIKeyInfo `json:"apiKey"`
	}
	if json.Unmarshal(w.Body.Bytes(), &created); w.Code != 200 || !strings.HasPrefix(created.Key, "axk_") {
		t.Fatalf("create key = %d %s", w.Code, w.Body.String())
	}
	if !a.ValidateAPIKeyScope(created.Key, "scim") {
		t.Fatal("the new key must validate for its scope")
	}
	if w := call("GET", "/auth/admin/apikeys", nil); w.Code != 200 || strings.Contains(w.Body.String(), created.Key) || !strings.Contains(w.Body.String(), `"ci"`) {
		t.Fatalf("list keys must name the key but never show it: %d %s", w.Code, w.Body.String())
	}
	if w := call("DELETE", "/auth/admin/apikeys/"+created.APIKey.ID, nil); w.Code != 200 {
		t.Fatalf("revoke key = %d", w.Code)
	}
	if a.ValidateAPIKeyScope(created.Key, "scim") {
		t.Fatal("a revoked key must stop validating")
	}
}

func TestChangePassword(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "pw@x.com", "old-password-123", true)
	c := newClient(t, a)
	c.login("pw@x.com", "old-password-123")

	if w := c.do("POST", "/auth/api/account/password", map[string]any{"current": "wrong-password-1", "new": "a-brand-new-pass-456"}); w.Code != http.StatusForbidden {
		t.Fatalf("a wrong current password = %d, want 403", w.Code)
	}
	if w := c.do("POST", "/auth/api/account/password", map[string]any{"current": "old-password-123", "new": "short"}); w.Code != http.StatusBadRequest {
		t.Fatalf("a password failing the policy = %d, want 400", w.Code)
	}
	if w := c.do("POST", "/auth/api/account/password", map[string]any{"current": "old-password-123", "new": "a-brand-new-pass-456"}); w.Code != 200 {
		t.Fatalf("change = %d %s", w.Code, w.Body.String())
	}
	if w := newClient(t, a).do("POST", "/auth/password/login", map[string]any{"email": "pw@x.com", "password": "old-password-123"}); w.Code == 200 {
		t.Fatal("the old password must stop working")
	}
	newClient(t, a).login("pw@x.com", "a-brand-new-pass-456")
}

func TestLogoutEndsTheSession(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "out@x.com", "hunter2hunter2", true)
	c := newClient(t, a)
	c.login("out@x.com", "hunter2hunter2")
	stolen := c.cookies["sweep_session"]
	replay := newClient(t, a)
	replay.cookies["sweep_session"] = stolen
	if me := decode(t, replay.do("GET", "/auth/me", nil)); me["email"] != "out@x.com" {
		t.Fatalf("control: the cookie must work before logout, got %v", me)
	}

	w := c.do("GET", "/auth/logout", nil)
	if w.Code != http.StatusFound || c.cookies["sweep_session"] != "" {
		t.Fatalf("logout = %d, session cookie %q", w.Code, c.cookies["sweep_session"])
	}
	// With a SessionStore, the old cookie is revoked server-side too: replaying it signs no one in.
	if me := decode(t, replay.do("GET", "/auth/me", nil)); me["email"] != nil {
		t.Fatalf("a logged-out session cookie must not be accepted: %v", me)
	}
}

func TestConfigFromEnv(t *testing.T) {
	for k, v := range map[string]string{
		"SESSION_SECRET":          "0123456789abcdef0123456789abcdef",
		"SESSION_SECRET_PREVIOUS": " old-old-old-old-old-old-old-old1 , ,old-old-old-old-old-old-old-old2",
		"APP_URL":                 "https://app.example.com/",
		"OWNER_EMAIL":             "  Owner@Example.COM ",
		"TRUSTED_ORIGINS":         "https://a.example.com, https://b.example.com",
		"OIDC_ISSUER":             "https://idp.example.com/",
		"OIDC_ALLOWED_GROUPS":     "admins,,ops",
		"COOKIE_SECURE":           "true",
		"HIBP_BREACH_CHECK":       "yes", // only "true" turns it on
		"BRAND_NAME":              " Acme ",
	} {
		t.Setenv(k, v)
	}
	c := authx.ConfigFromEnv()
	if string(c.SessionSecret) != "0123456789abcdef0123456789abcdef" || len(c.PreviousSessionSecrets) != 2 ||
		string(c.PreviousSessionSecrets[1]) != "old-old-old-old-old-old-old-old2" {
		t.Fatalf("secrets = %q / %q", c.SessionSecret, c.PreviousSessionSecrets)
	}
	if c.AppURL != "https://app.example.com" || c.Issuer != "https://idp.example.com" {
		t.Fatalf("trailing slashes must be trimmed: %q %q", c.AppURL, c.Issuer)
	}
	if c.OwnerEmail != "owner@example.com" || c.BrandName != "Acme" {
		t.Fatalf("owner/brand = %q %q", c.OwnerEmail, c.BrandName)
	}
	if len(c.TrustedOrigins) != 2 || c.TrustedOrigins[1] != "https://b.example.com" || len(c.AllowedGroups) != 2 {
		t.Fatalf("lists = %v %v", c.TrustedOrigins, c.AllowedGroups)
	}
	if !c.CookieSecure || c.BreachCheckHIBP {
		t.Fatalf("booleans: CookieSecure=%v BreachCheckHIBP=%v", c.CookieSecure, c.BreachCheckHIBP)
	}
}
