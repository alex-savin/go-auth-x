package authx_test

// Regression tests for the second review (of v0.13.0): opt-in __Host- cookie names, sign-out by POST,
// and the owner's own failed-password threshold.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// With HostCookies every cookie carries the __Host- prefix and Secure, and a cookie under the plain
// name — what a sibling subdomain can plant — is not read.
func TestHostCookies(t *testing.T) {
	if _, err := authx.New(context.Background(), authx.Config{SessionSecret: []byte(testSecret), AppURL: "http://app.example.com", HostCookies: true}); err == nil {
		t.Fatal("HostCookies without an https APP_URL must be refused")
	}
	s := memory.New()
	a, err := authx.New(context.Background(), authx.Config{SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", HostCookies: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(s)
	a.SetSessionStore(s)
	a.SetAuthorizer(s.Authorizer())
	a.SetLocalEnabled(true)
	seedUser(t, s, "u@x.com", "users-password-1", true)
	if a.CSRFCookieName() != "__Host-sweep_csrf" {
		t.Fatalf("CSRFCookieName = %q", a.CSRFCookieName())
	}

	c := newClient(t, a)
	w := c.do("POST", "/auth/password/login", map[string]any{"email": "u@x.com", "password": "users-password-1"})
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d %s", w.Code, w.Body.String())
	}
	for _, ck := range w.Result().Cookies() {
		if !strings.HasPrefix(ck.Name, "__Host-") || !ck.Secure || ck.Path != "/" || ck.Domain != "" {
			t.Fatalf("cookie %q: Secure=%v Path=%q Domain=%q — not a __Host- cookie", ck.Name, ck.Secure, ck.Path, ck.Domain)
		}
	}
	if c.cookies["__Host-sweep_session"] == "" || c.cookies["__Host-sweep_csrf"] == "" {
		t.Fatalf("cookies = %v", c.cookies)
	}
	// State-changing calls work with the token from the prefixed cookie…
	post := func(cookies map[string]string, csrf string) int {
		r := httptest.NewRequest("POST", "/auth/api/sessions/revoke-others", nil)
		r.Header.Set("Origin", "https://app.example.com")
		r.Header.Set("X-CSRF-Token", csrf)
		for k, v := range cookies {
			r.AddCookie(&http.Cookie{Name: k, Value: v})
		}
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, r)
		return rec.Code
	}
	if code := post(c.cookies, c.cookies["__Host-sweep_csrf"]); code != http.StatusOK {
		t.Fatalf("a call with the prefixed cookies = %d", code)
	}
	// …and the same values under the plain names are not a session.
	plain := map[string]string{"sweep_session": c.cookies["__Host-sweep_session"], "sweep_csrf": c.cookies["__Host-sweep_csrf"]}
	if code := post(plain, plain["sweep_csrf"]); code == http.StatusOK {
		t.Fatal("cookies under the plain names were accepted")
	}
	// Signing out clears them under their own names.
	w = c.do("GET", "/auth/logout", nil)
	cleared := 0
	for _, ck := range w.Result().Cookies() {
		if strings.HasPrefix(ck.Name, "__Host-") && ck.MaxAge < 0 && ck.Secure {
			cleared++
		}
	}
	if cleared < 2 {
		t.Fatalf("logout cleared %d __Host- cookies: %v", cleared, w.Result().Cookies())
	}
}

// Signing out is a POST with the CSRF token; GET can be turned off, so that a page the user visits
// can't sign them out.
func TestLogoutByPost(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "users-password-1", true)
	c := newClient(t, a)
	c.login("u@x.com", "users-password-1")

	r := httptest.NewRequest("POST", "/auth/logout", nil) // no CSRF token: a cross-site form
	r.Header.Set("Origin", "https://app.example.com")
	r.AddCookie(&http.Cookie{Name: "sweep_session", Value: c.cookies["sweep_session"]})
	r.AddCookie(&http.Cookie{Name: "sweep_csrf", Value: c.cookies["sweep_csrf"]})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !c.authenticated() {
		t.Fatalf("POST /auth/logout without the CSRF token = %d, signed in: %v", w.Code, c.authenticated())
	}
	if w := c.do("POST", "/auth/logout", nil); w.Code != http.StatusFound || c.authenticated() {
		t.Fatalf("POST /auth/logout = %d, signed in: %v", w.Code, c.authenticated())
	}

	store := memory.New()
	strict, err := authx.New(context.Background(), authx.Config{SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", DisableGetLogout: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = strict.Close() })
	strict.SetCredentialStore(store)
	strict.SetSessionStore(store)
	strict.SetAuthorizer(store.Authorizer())
	strict.SetLocalEnabled(true)
	seedUser(t, store, "u@x.com", "users-password-1", true)
	sc := newClient(t, strict)
	sc.login("u@x.com", "users-password-1")
	if w := sc.do("GET", "/auth/logout", nil); w.Code == http.StatusFound || !sc.authenticated() {
		t.Fatalf("GET /auth/logout with DisableGetLogout = %d, signed in: %v", w.Code, sc.authenticated())
	}
	if w := sc.do("POST", "/auth/logout", nil); w.Code != http.StatusFound || sc.authenticated() {
		t.Fatalf("POST /auth/logout = %d", w.Code)
	}
}

// The owner's password login pauses after enough failed attempts where a mailbox recovery exists.
// Exempt from any threshold, the owner's password was guessable at the per-IP limit's rate from
// every address an attacker has.
func TestOwnerPasswordLoginHasAThreshold(t *testing.T) {
	a, s, _ := newTestAuth(t) // has a mailer: the owner can still sign in by link
	seedUser(t, s, "owner@example.com", "owner-password-1", true)
	throttled := 0
	for i := range 40 {
		c := newClient(t, a)
		c.remote = "203.0.113." + string(rune('0'+i%10)) + string(rune('0'+i/10)) // many addresses: the per-IP limit doesn't apply
		if c.loginCode("owner@example.com", "wrong-password-guess") == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 || throttled > 12 {
		t.Fatalf("%d of 40 wrong owner passwords were throttled, want the ones past the threshold (30)", throttled)
	}

	// Without a mailer there is no other way in: the owner is not locked out.
	store := memory.New()
	bare, err := authx.New(context.Background(), authx.Config{SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", OwnerEmail: "owner@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bare.Close() })
	bare.SetCredentialStore(store)
	bare.SetAuthorizer(store.Authorizer())
	bare.SetLocalEnabled(true)
	seedUser(t, store, "owner@example.com", "owner-password-1", true)
	for i := range 40 {
		c := newClient(t, bare)
		c.remote = "203.0.113." + string(rune('0'+i%10)) + string(rune('0'+i/10))
		if code := c.loginCode("owner@example.com", "wrong-password-guess"); code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d: the owner was locked out with no mailer to recover by", i)
		}
	}
}

// The default trusted proxies cover the IPv6 private range like the IPv4 ones.
func TestDefaultTrustedProxiesIncludeIPv6Private(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	if !slices.Contains(authx.TrustedProxies(), "fc00::/7") {
		t.Fatalf("default trusted proxies = %v", authx.TrustedProxies())
	}
}
