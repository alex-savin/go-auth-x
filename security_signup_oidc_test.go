package authx_test

// Regression tests for the 2026-11 security audit: account squatting through signup (C1), the OIDC
// callback skipping the login funnel (C4), and OIDC email trust (C5).

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

const squatterPW = "squatter-chosen-pw-77"

func (c *client) loginCode(email, pw string) int {
	return c.do("POST", "/auth/password/login", map[string]any{"email": email, "password": pw}).Code
}

// A password set by a signup nobody proved never survives the mailbox owner's sign-in, whichever
// emailed proof they use.
func TestSignupSquatterPasswordDroppedByMailboxProof(t *testing.T) {
	for _, via := range []string{"magic link", "email code"} {
		t.Run(via, func(t *testing.T) {
			a, s, m := newTestAuth(t)
			if w := newClient(t, a).do("POST", "/auth/password/signup", map[string]any{"email": "victim@x.com", "password": squatterPW}); w.Code != 200 {
				t.Fatalf("squatter signup = %d", w.Code)
			}
			victim := newClient(t, a)
			if via == "magic link" {
				victim.do("POST", "/auth/email/request", map[string]any{"email": "victim@x.com"})
				tok := tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/login").text)[1]
				victim.do("GET", "/auth/email/login?token="+tok, nil)
			} else {
				victim.do("POST", "/auth/email-otp/send", map[string]any{"email": "victim@x.com"})
				code := sixDigits.FindStringSubmatch(m.waitFor(t, "sign-in code").text)[1]
				victim.do("POST", "/auth/email-otp/verify", map[string]any{"email": "victim@x.com", "code": code})
			}
			if victim.cookies["sweep_session"] == "" {
				t.Fatal("the mailbox owner must be signed in")
			}
			if code := newClient(t, a).loginCode("victim@x.com", squatterPW); code == 200 {
				t.Fatal("the squatter's password must not survive the owner's mailbox proof")
			}
			u, _ := s.UserByEmail("victim@x.com")
			if _, _, err := s.PasswordHash(u.ID); err == nil {
				t.Fatal("the unproven password must be removed")
			}
			// The owner sets a password of their own.
			if w := victim.do("POST", "/auth/api/account/password", map[string]any{"current": "", "new": "owners-own-password-1"}); w.Code != 200 {
				t.Fatalf("set own password = %d %s", w.Code, w.Body.String())
			}
			newClient(t, a).login("victim@x.com", "owners-own-password-1")
		})
	}
}

// The verify link keeps the signup's password only in the browser that signed up with it.
func TestSignupVerifyKeepsPasswordOnlyInSigningBrowser(t *testing.T) {
	signup := func(t *testing.T) (*authx.Authenticator, *client, string) {
		a, _, m := newTestAuth(t)
		b := newClient(t, a)
		if w := b.do("POST", "/auth/password/signup", map[string]any{"email": "new@x.com", "password": "my-chosen-password-1"}); w.Code != 200 {
			t.Fatalf("signup = %d", w.Code)
		}
		return a, b, tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/verify").text)[1]
	}

	t.Run("same browser keeps it", func(t *testing.T) {
		a, b, tok := signup(t)
		b.do("GET", "/auth/email/verify?token="+tok, nil)
		if b.cookies["sweep_session"] == "" || b.cookies["sweep_signup"] != "" {
			t.Fatalf("verify must sign in and clear the binding: %v", b.cookies)
		}
		newClient(t, a).login("new@x.com", "my-chosen-password-1")
	})
	t.Run("another browser drops it", func(t *testing.T) {
		a, _, tok := signup(t)
		other := newClient(t, a)
		other.do("GET", "/auth/email/verify?token="+tok, nil)
		if other.cookies["sweep_session"] == "" {
			t.Fatal("the mailbox owner must still be signed in")
		}
		if code := newClient(t, a).loginCode("new@x.com", "my-chosen-password-1"); code == 200 {
			t.Fatal("a password not bound to the verifying browser must be dropped")
		}
	})
	t.Run("a later signup can't ride the owner's link", func(t *testing.T) {
		a, owner, tok := signup(t)
		if w := newClient(t, a).do("POST", "/auth/password/signup", map[string]any{"email": "new@x.com", "password": squatterPW}); w.Code != 200 {
			t.Fatalf("squatter re-signup = %d", w.Code)
		}
		owner.do("GET", "/auth/email/verify?token="+tok, nil)
		if code := newClient(t, a).loginCode("new@x.com", squatterPW); code == 200 {
			t.Fatal("the squatter's replacement password must not be activated by the owner's link")
		}
	})
}

// A signup never puts a password on an operator-seeded placeholder (the owner claims it by signing in).
func TestSignupLeavesBootstrapRowAlone(t *testing.T) {
	a, s, _ := newTestAuth(t)
	u, err := s.UpsertUserOnLogin("bootstrap:owner@example.com", "owner@example.com", "Owner", false)
	if err != nil {
		t.Fatal(err)
	}
	if w := newClient(t, a).do("POST", "/auth/password/signup", map[string]any{"email": "owner@example.com", "password": squatterPW}); w.Code != 200 {
		t.Fatalf("signup = %d", w.Code)
	}
	if _, _, err := s.PasswordHash(u.ID); err == nil {
		t.Fatal("a signup must not set a password on a bootstrap row")
	}
}

// The OIDC callback goes through the login funnel: a disabled or banned user is refused, and a user
// with TOTP gets the second-factor step, not a session.
func TestOIDCCallbackEnforcesBlocksAndSecondFactor(t *testing.T) {
	idp := newFakeIdP(t)
	a, s := newOIDCTestAuth(t, idp, false)
	u := seedUser(t, s, "user@x.com", "", true)
	claims := jwt.MapClaims{"sub": "idp|user", "email": "user@x.com", "email_verified": true}

	_ = s.SetUserBan(u.ID, true, nil, "abuse")
	c := newClient(t, a)
	if w := idp.oidcSignIn(t, c, claims); w.Code != http.StatusForbidden || c.cookies["sweep_session"] != "" {
		t.Fatalf("a banned user via OIDC = %d %s", w.Code, w.Body.String())
	}
	_ = s.SetUserBan(u.ID, false, nil, "")

	_ = s.SetTOTPSecret(u.ID, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	_ = s.EnableTOTP(u.ID)
	c = newClient(t, a)
	w := idp.oidcSignIn(t, c, claims)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "mfa=required") ||
		c.cookies["sweep_session"] != "" || c.cookies["sweep_2fa_pending"] == "" {
		t.Fatalf("a TOTP user via OIDC must get the second-factor step: %d %q %v", w.Code, w.Header().Get("Location"), c.cookies)
	}
}

// email_verified: an explicit false is refused even with OIDC_ASSUME_VERIFIED (which only fills in
// an absent claim), and identities without an email never share an account.
func TestOIDCEmailTrust(t *testing.T) {
	idp := newFakeIdP(t)
	a, s := newOIDCTestAuth(t, idp, true)
	victim := seedUser(t, s, "victim@x.com", "victim-password-1", true)

	if w := idp.oidcSignIn(t, newClient(t, a), jwt.MapClaims{"sub": "idp|mallory", "email": "victim@x.com", "email_verified": false}); w.Code != http.StatusUnauthorized {
		t.Fatalf("explicit email_verified:false = %d, want 401", w.Code)
	}
	if u, _ := s.UserByID(victim.ID); u.Sub != victim.Sub {
		t.Fatal("the victim's account must not be rebound")
	}
	if w := idp.oidcSignIn(t, newClient(t, a), jwt.MapClaims{"sub": "idp|carol", "email": "carol@x.com"}); w.Code != http.StatusFound {
		t.Fatalf("an absent claim with OIDC_ASSUME_VERIFIED = %d, want a sign-in", w.Code)
	}

	idp.oidcSignIn(t, newClient(t, a), jwt.MapClaims{"sub": "idp|alice"})
	idp.oidcSignIn(t, newClient(t, a), jwt.MapClaims{"sub": "idp|bob"})
	alice, err1 := s.UserBySub("idp|alice")
	bob, err2 := s.UserBySub("idp|bob")
	if err1 != nil || err2 != nil || alice.ID == bob.ID || alice.EmailVerified {
		t.Fatalf("email-less identities must get separate, unverified accounts: %+v %+v %v %v", alice, bob, err1, err2)
	}
}

// An IdP subject in one of the library's own namespaces is refused (it would name, say, the
// SCIM-provisioned account "scim:alice").
func TestOIDCReservedSubjectRefused(t *testing.T) {
	idp := newFakeIdP(t)
	a, s := newOIDCTestAuth(t, idp, false)
	alice, _ := s.UpsertExternalUser("scim:alice", "alice@corp.com", "Alice", true)
	for _, sub := range []string{"scim:alice", "LDAP:bob", "local:x", "bootstrap:o@x.com", "social:google:1"} {
		if w := idp.oidcSignIn(t, newClient(t, a), jwt.MapClaims{"sub": sub, "email": "evil@x.com", "email_verified": true}); w.Code != http.StatusUnauthorized {
			t.Fatalf("subject %q = %d, want 401", sub, w.Code)
		}
	}
	if u, _ := s.UserByID(alice.ID); u.Email != "alice@corp.com" {
		t.Fatalf("the provisioned account was changed: %q", u.Email)
	}
}

// socialSignIn runs /auth/social/<name>/login → callback with an id_token carrying claims.
func (p *fakeIdP) socialSignIn(t *testing.T, c *client, name string, claims jwt.MapClaims) *httptest.ResponseRecorder {
	t.Helper()
	w := c.do("GET", "/auth/social/"+name+"/login", nil)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusFound {
		t.Fatalf("social login = %d %q", w.Code, w.Header().Get("Location"))
	}
	q := loc.Query()
	p.mu.Lock()
	p.next = jwt.MapClaims{"nonce": q.Get("nonce")}
	maps.Copy(p.next, claims)
	p.mu.Unlock()
	return c.do("GET", "/auth/social/"+name+"/callback?code=c&state="+url.QueryEscape(q.Get("state")), nil)
}

// A provider the user disconnected doesn't sign back in to their account by email (a compromised
// provider account would walk straight back in); the user reconnects it while signed in.
func TestUnlinkedProviderStaysDisconnected(t *testing.T) {
	idp := newFakeIdP(t)
	store := memory.New()
	a, err := authx.New(context.Background(), authx.Config{
		SessionSecret: []byte(testSecret), AppURL: "https://app.example.com",
		SocialOIDC: []authx.SocialOIDCProvider{{Name: "gitlab", Issuer: idp.srv.URL, ClientID: "app-client", ClientSecret: "s"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(store)
	a.SetSessionStore(store)
	a.SetLocalEnabled(true)
	seedUser(t, store, "u@x.com", "user-password-12", true)
	gl := jwt.MapClaims{"sub": "gl-1", "email": "u@x.com", "email_verified": true}

	c := newClient(t, a)
	if w := idp.socialSignIn(t, c, "gitlab", gl); w.Code != http.StatusFound {
		t.Fatalf("first gitlab sign-in = %d %s", w.Code, w.Body.String())
	}
	c.reauth("user-password-12")
	if w := c.do("DELETE", "/auth/api/identities/gitlab", nil); w.Code != http.StatusOK {
		t.Fatalf("unlink = %d %s", w.Code, w.Body.String())
	}
	if w := idp.socialSignIn(t, newClient(t, a), "gitlab", gl); w.Code != http.StatusConflict {
		t.Fatalf("the disconnected provider signing in = %d, want 409", w.Code)
	}
	// Being signed in is not asking to reconnect: any page can send a signed-in browser to the
	// provider's login.
	if w := idp.socialSignIn(t, c, "gitlab", gl); w.Code != http.StatusConflict {
		t.Fatalf("the provider's login in a signed-in browser, unasked = %d, want 409", w.Code)
	}
	// Reconnecting is the user's explicit, CSRF-checked request; then it signs in again.
	reconnect := func() {
		t.Helper()
		if w := c.do("POST", "/auth/api/identities/gitlab/connect", nil); w.Code != http.StatusOK || decode(t, w)["next"] != "/auth/social/gitlab/login" {
			t.Fatalf("connect = %d %s", w.Code, w.Body.String())
		}
		if w := idp.socialSignIn(t, c, "gitlab", gl); w.Code != http.StatusFound {
			t.Fatalf("reconnecting = %d %s", w.Code, w.Body.String())
		}
	}
	reconnect()
	if w := idp.socialSignIn(t, newClient(t, a), "gitlab", gl); w.Code != http.StatusFound {
		t.Fatalf("after reconnecting, gitlab sign-in = %d", w.Code)
	}
	// Disconnected a second time, it stays disconnected again (the record of the first disconnect
	// used to be spent by the reconnect, and could not be made again).
	if w := c.do("DELETE", "/auth/api/identities/gitlab", nil); w.Code != http.StatusOK {
		t.Fatalf("second unlink = %d %s", w.Code, w.Body.String())
	}
	if w := idp.socialSignIn(t, newClient(t, a), "gitlab", gl); w.Code != http.StatusConflict {
		t.Fatalf("after a second disconnect the provider signs in again: %d", w.Code)
	}
	reconnect()
}

// midSignupStore runs then() once, right after a read of a user by email: the moment a signup has
// read "unverified" and is about to spend a bcrypt before it writes its password.
type midSignupStore struct {
	authx.CredentialStore
	armed atomic.Bool
	then  func()
}

func (s *midSignupStore) UserByEmail(email string) (*authx.AuthUser, error) {
	u, err := s.CredentialStore.UserByEmail(email)
	if s.armed.CompareAndSwap(true, false) {
		s.then()
	}
	return u, err
}

// atomicMidSignupStore is midSignupStore over a store that makes the signup writes atomic itself.
type atomicMidSignupStore struct {
	*midSignupStore
	authx.SignupStore
}

// A signup in flight when the address's owner proves the mailbox doesn't leave its password on the
// account. The signup read "unverified" before hashing; written unconditionally afterwards, its
// password would sit on a verified account. Both with a store that makes the write conditional
// (SignupStore) and with one that leaves it to the Authenticator.
func TestSignupInFlightDuringMailboxProofSetsNoPassword(t *testing.T) {
	for _, kind := range []string{"store with atomic signup writes", "store without them"} {
		t.Run(kind, func(t *testing.T) {
			base := memory.New()
			mid := &midSignupStore{CredentialStore: base}
			var creds authx.CredentialStore = mid
			if kind == "store with atomic signup writes" {
				creds = atomicMidSignupStore{mid, base}
			}
			if _, atomic := creds.(authx.SignupStore); atomic != (kind == "store with atomic signup writes") {
				t.Fatalf("the test store is the wrong kind: SignupStore = %v", atomic)
			}
			m := &capMailer{}
			a, err := authx.New(context.Background(), authx.Config{
				SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", OwnerEmail: "owner@example.com",
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			a.SetCredentialStore(creds)
			a.SetDirectoryStore(base)
			a.SetSessionStore(base)
			a.SetMailer(m)
			a.SetAuthorizer(base.Authorizer())
			a.SetLocalEnabled(true)

			// The owner signs up for their own address and gets the verify link.
			owner := newClient(t, a)
			if w := owner.do("POST", "/auth/password/signup", map[string]any{"email": "victim@x.com", "password": "owners-own-password-1"}); w.Code != http.StatusOK {
				t.Fatalf("owner signup = %d", w.Code)
			}
			tok := tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/verify").text)[1]

			// Someone else's signup for the address reads the account, and the owner opens the link
			// before that signup writes.
			mid.then = func() {
				owner.do("GET", "/auth/email/verify?token="+tok, nil)
				if owner.cookies["sweep_session"] == "" {
					t.Error("the owner's verify link must sign them in")
				}
			}
			mid.armed.Store(true)
			if w := newClient(t, a).do("POST", "/auth/password/signup", map[string]any{"email": "victim@x.com", "password": squatterPW}); w.Code != http.StatusOK {
				t.Fatalf("the other signup = %d", w.Code)
			}
			if mid.armed.Load() {
				t.Fatal("the signup never read the account")
			}

			if u, _ := base.UserByEmail("victim@x.com"); !u.EmailVerified {
				t.Fatal("the owner's link must have verified the account")
			}
			if code := newClient(t, a).loginCode("victim@x.com", squatterPW); code == http.StatusOK {
				t.Fatal("a signup that finished after the mailbox was proven left its password on the account")
			}
			// The owner's own password — set and verified in one browser — is the one that stays.
			if code := newClient(t, a).loginCode("victim@x.com", "owners-own-password-1"); code != http.StatusOK {
				t.Fatalf("the owner's own password = %d", code)
			}
		})
	}
}
