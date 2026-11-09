package oidcprovider_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// TestApproveHonorsOfflineAccessDecision checks Decision's contract: "Scopes are those granted: a subset
// of the request's". A decision that leaves out offline_access should not yield a refresh token.
func TestApproveHonorsOfflineAccessDecision(t *testing.T) {
	h := setup(t)
	cid := h.publicClient() // registered with refresh_token, so the request carries offline_access
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	id := h.authorize(cid, nil)
	next, err := h.p.Approve(context.Background(), id, h.user.Sub, oidcprovider.Decision{Scopes: []string{"tree:read"}})
	if err != nil {
		t.Fatal(err)
	}
	st, tok := h.exchange(cid, h.code(next))
	if st != 200 {
		t.Fatalf("token = %d %v", st, tok)
	}
	if tok["refresh_token"] != nil {
		t.Fatalf("Decision{Scopes: [tree:read]} still granted offline_access (refresh_token issued, scope=%v)", tok["scope"])
	}
}

// TestEndSessionKeepsGrants checks that /end_session, given only an id_token_hint (no
// session cookie, no client authentication), does not end the user's OAuth grants.
func TestEndSessionKeepsGrants(t *testing.T) {
	h := setup(t)
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	idt := h.idToken(cid)
	access, _ := h.connect(cid, "conn")
	if _, err := h.p.Verify(context.Background(), access); err != nil {
		t.Fatal(err)
	}

	// A plain client: no cookies, no credentials.
	res, err := http.Get(h.srv.URL + "/oauth/end_session?" + url.Values{"id_token_hint": {idt}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if _, err := h.p.Verify(context.Background(), access); err != nil {
		t.Fatalf("an unauthenticated /end_session with only an id_token_hint revoked the user's grant (status %d): %v", res.StatusCode, err)
	}
}

// impersonating presents every session as an admin's impersonation of its user.
type impersonating struct{ oidcprovider.Sessions }

func (i impersonating) SessionOf(r *http.Request) *authx.SessionClaims {
	sc := i.Sessions.SessionOf(r)
	if sc != nil {
		cp := *sc
		cp.ImpersonatedBy = "local:admin"
		return &cp
	}
	return nil
}

// An admin impersonating a user can't approve OAuth grants in their name (tokens that would outlive
// the impersonation, unmarked).
func TestImpersonationCantApproveGrants(t *testing.T) {
	h := setup(t, func(c *oidcprovider.Config) { c.Auth = impersonating{c.Auth} })
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	if loc := h.loginStep(cid, nil); !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("an impersonation session must be refused, got %q", loc)
	}
}
