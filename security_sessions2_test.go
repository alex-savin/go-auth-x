package authx_test

// Regression tests for the second review (of v0.13.0): impersonation sessions changing the account,
// step-up by a weaker factor than the one being added to, and access that outlived an operator's
// password reset.

import (
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// globalKey stores a global API key with these scopes and returns its raw value.
func globalKey(t *testing.T, s *memory.Store, name string, scopes ...string) string {
	t.Helper()
	raw := "axk_" + name + "_0123456789"
	h := sha256.Sum256([]byte(raw))
	if _, err := s.CreateAPIKey(name, nil, scopes, raw[:12], h[:], nil); err != nil {
		t.Fatal(err)
	}
	return raw
}

// impersonate starts an impersonation of userID with an admin key and returns the session's client.
func impersonate(t *testing.T, a *authx.Authenticator, key, userID string) *client {
	t.Helper()
	c := newClient(t, a)
	c.bearer = key
	if w := c.do("POST", "/auth/admin/users/"+userID+"/impersonate", nil); w.Code != http.StatusOK || c.cookies["sweep_session"] == "" {
		t.Fatalf("impersonate = %d %s", w.Code, w.Body.String())
	}
	c.bearer = ""
	return c
}

// An impersonation session looks at the account; it doesn't change it. With the step-up waived for a
// user who has no password or TOTP, it could set a password, then sign in with it as the user —
// a session with no marker, and for the owner, the owner's.
func TestImpersonationSessionCantChangeTheAccount(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	owner := seedUser(t, s, "owner@example.com", "", true) // passwordless: a magic-link or passkey user
	seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner})
	key := globalKey(t, s, "admin", "admin")
	imp := impersonate(t, a, key, owner.ID)

	if me := decode(t, imp.do("GET", "/auth/me", nil)); me["impersonatedBy"] == "" || me["email"] != "owner@example.com" {
		t.Fatalf("an impersonation session reads as its user, marked: %v", me)
	}
	if w := imp.do("GET", "/auth/api/account", nil); w.Code != http.StatusOK {
		t.Fatalf("reading the account = %d", w.Code)
	}
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/auth/api/account/password", map[string]any{"new": "Launder-This-Pw-9931"}},
		{"POST", "/auth/api/account/email", map[string]any{"newEmail": "elsewhere@evil.example"}},
		{"DELETE", "/auth/api/account", nil},
		{"POST", "/auth/webauthn/register/begin", nil},
		{"POST", "/auth/2fa/totp/begin", nil},
		{"POST", "/auth/reauth", map[string]any{"password": "x"}},
		{"DELETE", "/auth/api/identities/google", nil},
		{"POST", "/auth/api/sessions/revoke-others", nil},
		{"POST", "/auth/org/invites", map[string]any{"email": "alt@evil.example", "role": "owner"}},
		{"POST", "/auth/org/members/" + owner.ID, map[string]any{"role": "member"}},
	} {
		if w := imp.do(call.method, call.path, call.body); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s under impersonation = %d %s, want 403", call.method, call.path, w.Code, w.Body.String())
		}
	}
	if _, _, err := s.PasswordHash(owner.ID); err == nil {
		t.Fatal("the impersonation session set a password on the account")
	}
	if _, err := s.UserByID(owner.ID); err != nil {
		t.Fatal("the impersonation session deleted the account")
	}
	// It can still switch the active org and end itself.
	if w := imp.do("POST", "/auth/org/switch", map[string]any{"org": ""}); w.Code == http.StatusForbidden {
		t.Fatalf("org switch under impersonation = %d", w.Code)
	}
	if w := imp.do("POST", "/auth/api/stop-impersonating", nil); w.Code != http.StatusOK {
		t.Fatalf("stop impersonating = %d %s", w.Code, w.Body.String())
	}
}

// An impersonation is attributed to what authorized it: the admin key, not whoever's session cookie
// the caller also sent.
func TestImpersonationIsAttributedToTheKeyThatStartedIt(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "bystander@x.com", "hunter2hunter2", true)
	target := seedUser(t, s, "target@x.com", "hunter2hunter2", true)
	key := globalKey(t, s, "admin", "admin")
	c := newClient(t, a)
	c.login("bystander@x.com", "hunter2hunter2")
	c.bearer = key
	if w := c.do("POST", "/auth/admin/users/"+target.ID+"/impersonate", nil); w.Code != http.StatusOK {
		t.Fatalf("impersonate = %d %s", w.Code, w.Body.String())
	}
	c.bearer = ""
	by, _ := decode(t, c.do("GET", "/auth/me", nil))["impersonatedBy"].(string)
	if len(by) < 8 || by[:7] != "apikey:" {
		t.Fatalf("impersonatedBy = %q, want the key (apikey:<id>)", by)
	}
}

// A TOTP user adds a sign-in method only after stepping up with a code. A passkey completes the
// second-factor step, so with a password-only step-up, someone holding a stolen session and the
// password — never a code — could add a passkey of their own and bypass the TOTP from then on.
func TestTOTPUserAddsAPasskeyOnlyAfterACodeStepUp(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "victim@x.com", "victim-password-1", true)
	victim := newClient(t, a)
	victim.login("victim@x.com", "victim-password-1")
	victim.reauth("victim-password-1")
	_, recovery := enrollTOTP(t, victim)

	thief := stolen(victim, victim)
	if w := thief.do("POST", "/auth/reauth", map[string]any{"password": "victim-password-1"}); w.Code != http.StatusOK {
		t.Fatalf("password re-auth = %d", w.Code)
	}
	if w := thief.do("POST", "/auth/webauthn/register/begin", nil); w.Code != http.StatusForbidden {
		t.Fatalf("passkey enrolment after a password-only step-up on a TOTP account = %d, want 403", w.Code)
	}
	// A password step-up still serves what it always did (here: asking for a change of address).
	if w := thief.do("POST", "/auth/api/account/email", map[string]any{"newEmail": "new@x.com"}); w.Code == http.StatusForbidden {
		t.Fatalf("an action gated on any step-up = %d", w.Code)
	}
	// The user, with a second-factor code (a recovery code here: enrollment just used this time step's).
	if w := victim.do("POST", "/auth/reauth", map[string]any{"code": recovery[0].(string)}); w.Code != http.StatusOK {
		t.Fatalf("code re-auth = %d %s", w.Code, w.Body.String())
	}
	if w := victim.do("POST", "/auth/webauthn/register/begin", nil); w.Code != http.StatusOK {
		t.Fatalf("passkey enrolment after a code step-up = %d %s", w.Code, w.Body.String())
	}
}

// An operator's password reset, like the user's own, ends what was signed in to the account: its
// sessions, the grants it gave OAuth clients, and a change of address it had pending.
func TestAdminPasswordResetEndsAllAccess(t *testing.T) {
	a, s, m := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-password-1", true)
	u := seedUser(t, s, "u@x.com", "phished-password-1", true)
	thief := newClient(t, a)
	thief.login("u@x.com", "phished-password-1")
	thief.reauth("phished-password-1")
	thief.do("POST", "/auth/api/account/email", map[string]any{"newEmail": "thief@evil.example"})
	change := tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/change").text)[1]
	if err := s.CreateOAuthGrant(&authx.OAuthGrant{ID: "g1", ClientID: "c", Subject: u.Sub, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	owner := newClient(t, a)
	owner.login("owner@example.com", "owner-password-1")
	if w := owner.do("POST", "/auth/admin/users/"+u.ID+"/password", map[string]any{"password": "Brand-New-Pw-77421"}); w.Code != http.StatusOK {
		t.Fatalf("admin reset = %d %s", w.Code, w.Body.String())
	}
	if w := thief.do("GET", "/auth/api/account", nil); w.Code == http.StatusOK {
		t.Fatal("a session from before the operator's reset still works")
	}
	if g, err := s.OAuthGrant("g1"); err == nil && g.RevokedAt == nil {
		t.Fatal("an OAuth grant from before the operator's reset is still live")
	}
	mine := newClient(t, a)
	mine.login("u@x.com", "Brand-New-Pw-77421")
	mine.do("GET", "/auth/email/change?token="+change, nil)
	if _, err := s.UserByEmail("thief@evil.example"); err == nil {
		t.Fatal("a change of address from before the operator's reset went through")
	}
}
