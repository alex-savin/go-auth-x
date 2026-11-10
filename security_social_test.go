package authx_test

// Regression tests for the second review (of v0.13.0): provisioned accounts on a social sign-in, a
// login flow's provider, email keys and Unicode, single-use WebAuthn challenges, and a blocked user's
// cookie without a SessionStore.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

func newSocialAuth(t *testing.T, idp *fakeIdP, providers ...string) (*authx.Authenticator, *memory.Store) {
	t.Helper()
	store := memory.New()
	var ps []authx.SocialOIDCProvider
	for _, p := range providers {
		ps = append(ps, authx.SocialOIDCProvider{Name: p, Issuer: idp.srv.URL, ClientID: "app-client", ClientSecret: "s"})
	}
	a, err := authx.New(context.Background(), authx.Config{SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", SocialOIDC: ps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(store)
	a.SetDirectoryStore(store)
	a.SetSessionStore(store)
	a.SetLocalEnabled(true)
	return a, store
}

// An account an org's SCIM (or SCIM, or LDAP) provisioned and its user hasn't verified yet is kept
// when that user signs in with a provider that verifies the address. Replaced with a fresh account,
// as a signup squatter's is, the person lost their org and group memberships and the IdP its handle
// on them — it could no longer update or deprovision them.
func TestSocialSignInKeepsAProvisionedAccount(t *testing.T) {
	idp := newFakeIdP(t)
	a, s := newSocialAuth(t, idp, "gitlab")
	u, err := s.UpsertExternalUser("scim:org1:alice", "alice@x.com", "Alice", false)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := s.CreateGroup("staff", "")
	_ = s.AddUserToGroup(u.ID, g.ID)
	_ = s.SetPasswordHash(u.ID, "a-password-someone-signed-up-with", "bcrypt") // anyone can sign up for the address

	c := newClient(t, a)
	if w := idp.socialSignIn(t, c, "gitlab", jwt.MapClaims{"sub": "gl-alice", "email": "alice@x.com", "email_verified": true}); w.Code != http.StatusFound {
		t.Fatalf("sign-in = %d %s", w.Code, w.Body.String())
	}
	got, err := s.UserByEmail("alice@x.com")
	if err != nil || got.ID != u.ID || got.Sub != "scim:org1:alice" || !got.EmailVerified {
		t.Fatalf("the provisioned account must be kept and verified: %+v, %v", got, err)
	}
	if gs, _ := s.UserGroups(u.ID); len(gs) != 1 {
		t.Fatalf("its memberships must stay: %v", gs)
	}
	if _, _, err := s.PasswordHash(u.ID); err == nil {
		t.Fatal("a password from before the proof must not be kept")
	}
	if me := decode(t, c.do("GET", "/auth/me", nil)); me["email"] != "alice@x.com" {
		t.Fatalf("signed in as %v", me)
	}
	// A squatter's own signup is still replaced, not adopted.
	sq, _ := s.CreateLocalUser("bob@x.com", "Squatter")
	if w := idp.socialSignIn(t, newClient(t, a), "gitlab", jwt.MapClaims{"sub": "gl-bob", "email": "bob@x.com", "email_verified": true}); w.Code != http.StatusFound {
		t.Fatalf("sign-in over a squatter = %d %s", w.Code, w.Body.String())
	}
	if bob, _ := s.UserByEmail("bob@x.com"); bob == nil || bob.ID == sq.ID {
		t.Fatalf("a squatter's unverified signup must be replaced: %+v", bob)
	}
}

// A login flow is finished at the provider it was started with.
func TestSocialFlowIsBoundToItsProvider(t *testing.T) {
	idp := newFakeIdP(t)
	a, _ := newSocialAuth(t, idp, "gitlab", "okta")
	c := newClient(t, a)
	w := c.do("GET", "/auth/social/gitlab/login", nil)
	loc, _ := url.Parse(w.Header().Get("Location"))
	state := loc.Query().Get("state")
	if w.Code != http.StatusFound || state == "" {
		t.Fatalf("login = %d", w.Code)
	}
	if w := c.do("GET", "/auth/social/okta/callback?code=c&state="+url.QueryEscape(state), nil); w.Code != http.StatusBadRequest {
		t.Fatalf("gitlab's flow at okta's callback = %d %s, want 400", w.Code, w.Body.String())
	}
}

// Two addresses that differ by a letter Unicode lower-cases into an ASCII one are two addresses:
// "vİctim@x.com" (U+0130) is not "victim@x.com". Keyed alike, a provider that verified the first
// for whoever registered it would sign that person in to the second's account.
func TestEmailKeysDontFoldUnicodeIntoASCII(t *testing.T) {
	if got := authx.NormalizeEmail("  Victim@X.com "); got != "victim@x.com" {
		t.Fatalf("NormalizeEmail = %q", got)
	}
	if got := authx.NormalizeEmail("ÉRIC@x.com"); got != "éric@x.com" {
		t.Fatalf("non-ASCII letters still lower-case to their own lower case: %q", got)
	}
	for lookalike, plain := range map[string]string{"vİctim@x.com": "victim@x.com", "Kate@x.com": "kate@x.com"} {
		if authx.NormalizeEmail(lookalike) == plain {
			t.Fatalf("%q is keyed as %q", lookalike, plain)
		}
		s := memory.New()
		u, _ := s.CreateLocalUser(plain, "Real")
		if got, err := s.UserByEmail(lookalike); err == nil && got.ID == u.ID {
			t.Fatalf("the store finds %q's account under %q", plain, lookalike)
		}
	}
}

// Without a SessionStore a ban doesn't end a cookie; the banned user's cookie still drives no
// self-service call.
func TestBlockedUsersCookieDrivesNoAccountCall(t *testing.T) {
	s := memory.New()
	a, err := authx.New(context.Background(), authx.Config{SessionSecret: []byte(testSecret), AppURL: "https://app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(s) // no SessionStore: sessions are stateless
	a.SetAuthorizer(s.Authorizer())
	a.SetLocalEnabled(true)
	u := seedUser(t, s, "u@x.com", "users-password-1", true)
	c := newClient(t, a)
	c.login("u@x.com", "users-password-1")
	if w := c.do("GET", "/auth/api/account", nil); w.Code != http.StatusOK {
		t.Fatalf("account = %d", w.Code)
	}
	_ = s.SetUserBan(u.ID, true, nil, "abuse")
	if w := c.do("GET", "/auth/api/account", nil); w.Code == http.StatusOK {
		t.Fatal("a banned user's cookie still reads the account")
	}
	if w := c.do("POST", "/auth/api/account/password", map[string]any{"current": "users-password-1", "new": "another-password-22"}); w.Code == http.StatusOK {
		t.Fatal("a banned user's cookie still changes the password")
	}
}

// A WebAuthn ceremony's challenge is used once: a finish request replayed with its cookie doesn't get
// a second try at the same challenge.
func TestWebauthnChallengeIsSingleUse(t *testing.T) {
	a, _, _ := newTestAuth(t)
	c := newClient(t, a)
	if w := c.do("POST", "/auth/webauthn/login/begin", nil); w.Code != http.StatusOK {
		t.Fatalf("begin = %d", w.Code)
	}
	captured := map[string]string{}
	for k, v := range c.cookies {
		captured[k] = v
	}
	first := c.do("POST", "/auth/webauthn/login/finish", map[string]any{"id": "AAAA"})
	replay := &client{t: t, h: a.Handler(), cookies: captured}
	second := replay.do("POST", "/auth/webauthn/login/finish", map[string]any{"id": "AAAA"})
	if first.Code == http.StatusOK || second.Code != http.StatusBadRequest || !strings.Contains(second.Body.String(), "expired") {
		t.Fatalf("first finish = %d %s; replay with the same cookie = %d %s, want 400 expired", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	if first.Code == http.StatusBadRequest && strings.Contains(first.Body.String(), "expired") {
		t.Fatalf("the first use of the challenge must reach the ceremony: %s", first.Body.String())
	}
}

// A key's groups and scopes are single tokens: a store may keep them comma-separated.
func TestAPIKeyScopesAndGroupsAreSingleTokens(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-password-1", true)
	oc := newClient(t, a)
	oc.login("owner@example.com", "owner-password-1")
	for _, body := range []map[string]any{
		{"name": "k", "scopes": []string{"scim,*"}},
		{"name": "k", "groups": []string{"a,admins"}},
		{"name": "k", "scopes": []string{""}},
	} {
		if w := oc.do("POST", "/auth/admin/apikeys", body); w.Code != http.StatusBadRequest {
			t.Fatalf("create key %v = %d, want 400", body, w.Code)
		}
	}
}
