package authx_test

// Regression tests for the 2026-11 security audit: account squatting through signup (C1), the OIDC
// callback skipping the login funnel (C4), and OIDC email trust (C5).

import (
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	authx "github.com/alex-savin/go-auth-x"
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
	a, s := newOIDCAuth(t, idp, false)
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
	a, s := newOIDCAuth(t, idp, true)
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
