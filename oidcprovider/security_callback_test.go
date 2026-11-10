package oidcprovider_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// browser is another browser: its own cookies, redirects not followed.
func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// startAs starts an authorization request from client c (whoever that is) and returns the login link
// zitadel answers with, and the request's id.
func (h *harness) startAs(c *http.Client, clientID string) (loginURL, id string) {
	h.t.Helper()
	_, ch := pkce()
	res := h.get(c, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"state": {"st8"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}, "resource": {h.srv.URL + "/mcp"}}.Encode())
	loginURL = res.Header.Get("Location")
	if res.StatusCode != http.StatusFound || !strings.Contains(loginURL, "/oauth/login?id=") {
		h.t.Fatalf("authorize = %d %q", res.StatusCode, loginURL)
	}
	return loginURL, strings.SplitN(loginURL, "id=", 2)[1]
}

// noCode fails the test when a callback response hands out a code.
func (h *harness) noCode(who string, res *http.Response) {
	h.t.Helper()
	if loc := res.Header.Get("Location"); strings.Contains(loc, "code=") || res.StatusCode == http.StatusFound {
		h.t.Fatalf("%s: callback = %d %q", who, res.StatusCode, loc)
	}
}

// The callback issues an approved request's code only in the browser of the user who signed in for
// it, and once. Whoever starts a request knows its id: they could start one with their own PKCE
// verifier, have a signed-in user open its link and approve a genuine client, and collect the code
// from the callback themselves.
func TestCallbackIssuesTheCodeOnlyToTheRequestsUser(t *testing.T) {
	t.Run("with a consent screen", func(t *testing.T) {
		h := setup(t)
		cid := h.publicClient()
		stranger := browser() // no session
		loginURL, id := h.startAs(stranger, cid)

		h.signIn(h.web, "u@x.com", "correct horse battery staple")
		if loc := h.get(h.web, loginURL).Header.Get("Location"); !strings.HasPrefix(loc, "/consent?id=") {
			t.Fatalf("login step = %q", loc)
		}
		next, err := h.p.Approve(context.Background(), id, h.user.Sub, oidcprovider.Decision{})
		if err != nil {
			t.Fatal(err)
		}

		h.noCode("no session", h.get(stranger, next))
		other := browser() // signed in, as someone else
		h.seed("other@x.com", "another horse battery staple")
		h.signIn(other, "other@x.com", "another horse battery staple")
		h.noCode("another user's session", h.get(other, next))

		// The user's own browser still completes the request — once.
		code := h.code(next)
		h.noCode("a second visit", h.get(h.web, next))
		h.noCode("no session, after the code was issued", h.get(stranger, next))
		if st, tok := h.exchange(cid, code); st != http.StatusOK {
			t.Fatalf("the code issued to the user's browser = %d %v", st, tok)
		}
	})
	t.Run("without a consent screen", func(t *testing.T) {
		h := setup(t, func(c *oidcprovider.Config) { c.ConsentURL, c.Registration = nil, false })
		if _, err := h.p.RegisterClient(authx.OAuthClient{ID: "first-party", RedirectURIs: []string{redirect}, AuthMethod: "none"}); err != nil {
			t.Fatal(err)
		}
		stranger := browser()
		loginURL, _ := h.startAs(stranger, "first-party")

		// Following the link while signed in approves the request (no consent screen)…
		h.signIn(h.web, "u@x.com", "correct horse battery staple")
		next := h.get(h.web, loginURL).Header.Get("Location")
		if !strings.Contains(next, "/oauth/authorize/callback?id=") {
			t.Fatalf("login step = %q", next)
		}
		// …but the code goes to the user's browser, on its way to the client, and nowhere else.
		h.noCode("no session, before the user's browser arrives", h.get(stranger, next))
		_ = h.code(next)
		h.noCode("no session, after", h.get(stranger, next))
	})
}

// impersonatingWhen presents every session as an admin's impersonation of its user while *on.
type impersonatingWhen struct {
	oidcprovider.Sessions
	on *bool
}

func (i impersonatingWhen) SessionOf(r *http.Request) *authx.SessionClaims {
	sc := i.Sessions.SessionOf(r)
	if sc == nil || !*i.on {
		return sc
	}
	cp := *sc
	cp.ImpersonatedBy = "local:admin"
	return &cp
}

// An admin's impersonation session doesn't collect a code for a request its user approved.
func TestCallbackRefusesAnImpersonationSession(t *testing.T) {
	impersonated := false
	h := setup(t, func(c *oidcprovider.Config) { c.Auth = impersonatingWhen{c.Auth, &impersonated} })
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	id := h.authorize(cid, nil)
	next, err := h.p.Approve(context.Background(), id, h.user.Sub, oidcprovider.Decision{})
	if err != nil {
		t.Fatal(err)
	}
	impersonated = true
	h.noCode("an impersonation session", h.get(h.web, next))
	impersonated = false
	_ = h.code(next) // the user's own session still gets it
}

// The built-in consent endpoint refuses an impersonation session, as the login step does: once the
// user's own browser has signed in for a request, an admin impersonating them could otherwise approve
// it in their name.
func TestConsentEndpointRefusesAnImpersonationSession(t *testing.T) {
	impersonated := false
	h := setup(t, func(c *oidcprovider.Config) { c.Auth = impersonatingWhen{c.Auth, &impersonated} })
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	id := h.authorize(cid, nil)
	if res := h.get(h.web, "/oauth/consent?id="+id); res.StatusCode != http.StatusOK {
		t.Fatalf("the user's own session reads the request: %d", res.StatusCode)
	}
	impersonated = true
	if res := h.get(h.web, "/oauth/consent?id="+id); res.StatusCode != http.StatusForbidden {
		t.Fatalf("an impersonation session on the consent endpoint = %d, want 403", res.StatusCode)
	}
}
