package oidcprovider_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// loginStep runs /authorize (with extra parameters) and the login step, returning where the login
// step sends the browser.
func (h *harness) loginStep(clientID string, extra url.Values) string {
	h.t.Helper()
	_, ch := pkce()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"st8"},
		"code_challenge": {ch}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		q[k] = v
	}
	res := h.get(h.web, "/oauth/authorize?"+q.Encode())
	if loc := res.Header.Get("Location"); res.StatusCode != 302 || !strings.Contains(loc, "/oauth/login?id=") {
		h.t.Fatalf("authorize = %d %q", res.StatusCode, loc)
	}
	return h.get(h.web, res.Header.Get("Location")).Header.Get("Location")
}

// prompt=login wants a sign-in made for this request: an older session is sent to sign in again,
// and coming back without having done so fails the request instead of looping.
func TestPromptLoginRequiresFreshSignIn(t *testing.T) {
	h := setup(t, func(c *oidcprovider.Config) {
		c.ReauthURL = func(returnTo string) string { return "/reauth?next=" + url.QueryEscape(returnTo) }
	})
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	time.Sleep(1100 * time.Millisecond) // the session's sign-in is now strictly before the request

	loc := h.loginStep(cid, url.Values{"prompt": {"login"}})
	if !strings.HasPrefix(loc, "/reauth?next=") {
		t.Fatalf("an older session must be sent to sign in again, got %q", loc)
	}
	back, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/reauth?next="))

	// The app's page sends the signed-in user straight back: login_required, not a loop.
	if to := h.get(h.web, back).Header.Get("Location"); !strings.HasPrefix(to, redirect) || !strings.Contains(to, "error=login_required") {
		t.Fatalf("coming back still stale must fail with login_required, got %q", to)
	}

	// Signing in again during the request satisfies it.
	loc = h.loginStep(cid, url.Values{"prompt": {"login"}})
	back, _ = url.QueryUnescape(strings.TrimPrefix(loc, "/reauth?next="))
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	if to := h.get(h.web, back).Header.Get("Location"); !strings.HasPrefix(to, "/consent?id=") {
		t.Fatalf("after signing in again the request must go on to consent, got %q", to)
	}
}

// max_age: a session signed in within it goes straight on; prompt=none can't ask for a sign-in.
func TestMaxAge(t *testing.T) {
	h := setup(t)
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	if loc := h.loginStep(cid, url.Values{"max_age": {"3600"}}); !strings.HasPrefix(loc, "/consent?id=") {
		t.Fatalf("a sign-in within max_age must go on to consent, got %q", loc)
	}
	time.Sleep(1100 * time.Millisecond)
	if loc := h.loginStep(cid, url.Values{"max_age": {"0"}}); !strings.HasPrefix(loc, "/welcome?next=") {
		t.Fatalf("max_age=0 must ask for a sign-in (at LoginURL by default), got %q", loc)
	}
	if loc := h.loginStep(cid, url.Values{"max_age": {"0"}, "prompt": {"none"}}); !strings.Contains(loc, "error=login_required") {
		t.Fatalf("prompt=none must fail rather than ask for a sign-in, got %q", loc)
	}
}

// The ID token's auth_time is when the user signed in, not when they approved.
func TestAuthTimeIsSignInTime(t *testing.T) {
	h := setup(t)
	cid := h.publicClient()
	before := time.Now()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	after := time.Now()                 // the session's sign-in is stamped in [before, after]
	time.Sleep(2100 * time.Millisecond) // the approval lands at least two whole seconds after that
	tok := h.idToken(cid)
	jws, err := jose.ParseSignedCompact(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		AuthTime int64 `json:"auth_time"`
	}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims); err != nil {
		t.Fatal(err)
	}
	// auth_time has whole seconds.
	if got := time.Unix(claims.AuthTime, 0); got.Before(before.Truncate(time.Second)) || got.After(after) {
		t.Fatalf("auth_time = %v, want the sign-in, between %v and %v (not the later approval)", got, before, after)
	}
}

// RevokeUser ends every grant of a user ("disconnect all apps").
func TestRevokeUser(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	a1, _ := h.connect(cid, "c1")
	a2, _ := h.connect(cid, "c2")
	if err := h.p.RevokeUser(ctx, h.user.Sub); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{a1, a2} {
		if _, err := h.p.Verify(ctx, a); err == nil {
			t.Fatal("RevokeUser must end all of the user's grants")
		}
	}
}
