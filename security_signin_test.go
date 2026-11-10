package authx_test

// Regression tests for the second review (of v0.13.0): the sign-in funnel failing open on store
// errors, the post-login redirect, pending email changes, links bound to their account, the signup
// cookie as an oracle, and unbounded names and bodies.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// failingStore is a memory store whose reads of a user by subject, of TOTP, or of the failure
// history can be made to fail, as a database does under load or during a failover.
type failingStore struct {
	*memory.Store
	failSub, failTOTP, failHistory atomic.Bool
}

var errStoreDown = errors.New("database is locked")

func (f *failingStore) UserBySub(sub string) (*authx.AuthUser, error) {
	if f.failSub.Load() {
		return nil, errStoreDown
	}
	return f.Store.UserBySub(sub)
}

func (f *failingStore) TOTP(userID string) (*authx.TOTPInfo, error) {
	if f.failTOTP.Load() {
		return nil, errStoreDown
	}
	return f.Store.TOTP(userID)
}

func (f *failingStore) RecentFailures(email string, since time.Time) (int, error) {
	if f.failHistory.Load() {
		return 0, errStoreDown
	}
	return f.Store.RecentFailures(email, since)
}

func newFailingAuth(t *testing.T) (*authx.Authenticator, *failingStore) {
	t.Helper()
	fs := &failingStore{Store: memory.New()}
	a, err := authx.New(context.Background(), authx.Config{
		SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", OwnerEmail: "owner@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(fs)
	a.SetDirectoryStore(fs.Store)
	a.SetTwoFactorStore(fs)
	a.SetSessionStore(fs.Store)
	a.SetAuthorizer(fs.Store.Authorizer())
	a.SetLocalEnabled(true)
	return a, fs
}

// A store error during sign-in ends the sign-in. Read as "no such user" or "no second factor", it
// would let a password alone sign in to a TOTP account, and a banned user through.
func TestSignInFailsClosedOnStoreErrors(t *testing.T) {
	a, fs := newFailingAuth(t)
	u := seedUser(t, fs.Store, "totp@x.com", "correct-horse-battery", true)
	_ = fs.SetTOTPSecret(u.ID, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	_ = fs.EnableTOTP(u.ID)
	login := func() (*client, *httptest.ResponseRecorder) {
		c := newClient(t, a)
		return c, c.do("POST", "/auth/password/login", map[string]any{"email": "totp@x.com", "password": "correct-horse-battery"})
	}
	if c, w := login(); c.cookies["sweep_session"] != "" || !strings.Contains(w.Body.String(), "twoFactorRequired") {
		t.Fatalf("a healthy store asks for the second factor: %d %s", w.Code, w.Body.String())
	}
	for name, fail := range map[string]*atomic.Bool{"the user": &fs.failSub, "TOTP": &fs.failTOTP, "the failure history": &fs.failHistory} {
		fail.Store(true)
		c, w := login()
		fail.Store(false)
		if c.cookies["sweep_session"] != "" || w.Code == http.StatusOK {
			t.Fatalf("a failed read of %s signed the user in: %d %s", name, w.Code, w.Body.String())
		}
	}

	// A session can't use a failed read to add a factor without a step-up, or to replace enabled TOTP.
	pw := seedUser(t, fs.Store, "pw@x.com", "another-horse-battery", true)
	c := newClient(t, a)
	c.login("pw@x.com", "another-horse-battery")
	_ = fs.SetTOTPSecret(pw.ID, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	_ = fs.EnableTOTP(pw.ID)
	c.reauth("another-horse-battery")
	fs.failTOTP.Store(true)
	w := c.do("POST", "/auth/2fa/totp/begin", nil)
	fs.failTOTP.Store(false)
	if w.Code == http.StatusOK {
		t.Fatalf("a failed TOTP read let enrollment start over: %d %s", w.Code, w.Body.String())
	}
	if info, _ := fs.Store.TOTP(pw.ID); info == nil || !info.Enabled {
		t.Fatal("the enabled TOTP was replaced")
	}
}

// The post-login redirect stays on this site for every spelling: http.Redirect cleans the path it is
// given, so a target has to be validated as it will be emitted.
func TestPostLoginRedirectStaysLocal(t *testing.T) {
	a, s, m := newTestAuth(t)
	seedUser(t, s, "victim@x.com", "", true)
	for _, next := range []string{`/./\evil.example`, `/a/../\evil.example`, `/.//evil.example`, `/a/..//evil.example`, `/x\..\evil.example`, `//evil.example`, `/\evil.example`} {
		m.mu.Lock()
		m.msgs = nil
		m.mu.Unlock()
		c := newClient(t, a)
		c.do("POST", "/auth/email/request", map[string]any{"email": "victim@x.com", "next": next})
		link := m.waitFor(t, "/auth/email/login").text
		link = link[strings.Index(link, "/auth/email/login"):]
		if i := strings.IndexAny(link, " \n\r"); i >= 0 {
			link = link[:i]
		}
		w := c.do("GET", link, nil)
		loc := w.Header().Get("Location")
		if w.Code != http.StatusFound || c.cookies["sweep_session"] == "" {
			t.Fatalf("next=%q: sign-in = %d %q", next, w.Code, loc)
		}
		if !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") || strings.Contains(loc, `\`) {
			t.Fatalf("next=%q redirects to %q", next, loc)
		}
	}
}

// A pending change of address is confirmed in a browser signed in to the account, and dies when the
// account is taken back. Someone with a stolen password could ask for the change, wait out the
// owner's password reset, and then open the link mailed to them with no session at all.
func TestPendingEmailChangeDiesWithTheAccountsRecovery(t *testing.T) {
	request := func(t *testing.T) (*authx.Authenticator, *memory.Store, *capMailer, *client, string) {
		a, s, m := newTestAuth(t)
		seedUser(t, s, "victim@x.com", "phished-password-1", true)
		thief := newClient(t, a)
		thief.login("victim@x.com", "phished-password-1")
		thief.reauth("phished-password-1")
		if w := thief.do("POST", "/auth/api/account/email", map[string]any{"newEmail": "thief@evil.example"}); w.Code != http.StatusOK {
			t.Fatalf("change request = %d %s", w.Code, w.Body.String())
		}
		return a, s, m, thief, tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/change").text)[1]
	}
	moved := func(s *memory.Store) bool {
		_, err := s.UserByEmail("thief@evil.example")
		return err == nil
	}

	t.Run("no session, no change", func(t *testing.T) {
		a, s, _, _, tok := request(t)
		w := newClient(t, a).do("GET", "/auth/email/change?token="+tok, nil)
		if moved(s) {
			t.Fatal("the link changed the address without a session")
		}
		if loc := w.Header().Get("Location"); !strings.Contains(loc, "/login?") || !strings.Contains(loc, "next=") {
			t.Fatalf("an unsigned-in confirm should send the user to sign in and come back, got %q", loc)
		}
	})
	t.Run("another account's session doesn't confirm it", func(t *testing.T) {
		a, s, _, _, tok := request(t)
		seedUser(t, s, "other@x.com", "others-own-password-1", true)
		other := newClient(t, a)
		other.login("other@x.com", "others-own-password-1")
		other.do("GET", "/auth/email/change?token="+tok, nil)
		if moved(s) {
			t.Fatal("another account's session confirmed the change")
		}
	})
	t.Run("the account's own session confirms it", func(t *testing.T) {
		a, s, _, thief, tok := request(t)
		// Opening it signed out first doesn't spend the link.
		newClient(t, a).do("GET", "/auth/email/change?token="+tok, nil)
		thief.do("GET", "/auth/email/change?token="+tok, nil)
		if !moved(s) {
			t.Fatal("the signed-in account's own confirmation must go through")
		}
	})
	t.Run("a password reset cancels it", func(t *testing.T) {
		a, s, m, thief, tok := request(t)
		v := newClient(t, a)
		v.do("POST", "/auth/password/reset/request", map[string]any{"email": "victim@x.com"})
		reset := tokenRe.FindStringSubmatch(m.waitFor(t, "/reset?token=").text)[1]
		if w := v.do("POST", "/auth/password/reset/confirm", map[string]any{"token": reset, "password": "brand-new-pw-after-reset"}); w.Code != http.StatusOK {
			t.Fatalf("reset = %d %s", w.Code, w.Body.String())
		}
		thief.do("GET", "/auth/email/change?token="+tok, nil) // its session ended with the reset
		// Even a session of the account no longer confirms a change from before the reset.
		v.login("victim@x.com", "brand-new-pw-after-reset")
		v.do("GET", "/auth/email/change?token="+tok, nil)
		if moved(s) {
			t.Fatal("a change of address requested before the reset went through after it")
		}
	})
	t.Run("a password change and signing out the other sessions cancel it", func(t *testing.T) {
		for _, how := range []string{"password change", "sign out others"} {
			a, s, _, thief, tok := request(t)
			v := newClient(t, a)
			v.login("victim@x.com", "phished-password-1")
			if how == "password change" {
				if w := v.do("POST", "/auth/api/account/password", map[string]any{"current": "phished-password-1", "new": "brand-new-pw-after-change"}); w.Code != http.StatusOK {
					t.Fatalf("change = %d %s", w.Code, w.Body.String())
				}
			} else if w := v.do("POST", "/auth/api/sessions/revoke-others", nil); w.Code != http.StatusOK {
				t.Fatalf("revoke others = %d %s", w.Code, w.Body.String())
			}
			thief.do("GET", "/auth/email/change?token="+tok, nil)
			v.do("GET", "/auth/email/change?token="+tok, nil)
			if moved(s) {
				t.Fatalf("%s: the pending change of address survived", how)
			}
		}
	})
}

// A sign-in or verify link signs in the account it was mailed for. After that account leaves the
// address and someone else takes it, the old link is not a way in to the newcomer's account.
func TestEmailLinkIsForTheAccountItWasMailedFor(t *testing.T) {
	a, s, m := newTestAuth(t)
	old := seedUser(t, s, "shared@x.com", "", true)
	c := newClient(t, a)
	c.do("POST", "/auth/email/request", map[string]any{"email": "shared@x.com"})
	tok := tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/login").text)[1]
	if err := s.SetEmail(old.ID, "moved@x.com"); err != nil {
		t.Fatal(err)
	}
	seedUser(t, s, "shared@x.com", "newcomers-own-password-1", true)
	c.do("GET", "/auth/email/login?token="+tok, nil)
	if c.cookies["sweep_session"] != "" {
		t.Fatal("a link mailed for one account signed in to another that now holds the address")
	}
}

// Signup answers the same for a registered address as for a new one — the cookie it sets included.
func TestSignupSetsItsCookieForRegisteredAddressesToo(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "exists@x.com", "some-password-123", true)
	for _, email := range []string{"exists@x.com", "fresh@x.com"} {
		c := newClient(t, a)
		if w := c.do("POST", "/auth/password/signup", map[string]any{"email": email, "password": "probe-password-9"}); w.Code != http.StatusOK {
			t.Fatalf("signup %s = %d", email, w.Code)
		}
		if c.cookies["sweep_signup"] == "" {
			t.Fatalf("signup for %s set no signup cookie: its absence tells the two apart", email)
		}
	}
	// The registered account's password is untouched, and the cookie keeps nothing at verify.
	newClient(t, a).login("exists@x.com", "some-password-123")
	if code := newClient(t, a).loginCode("exists@x.com", "probe-password-9"); code == http.StatusOK {
		t.Fatal("a signup changed a registered account's password")
	}
}

// A display name can't make an account's session cookie too large for a browser to keep, whether a
// signup chose it or a directory stored it.
func TestOversizedNameDoesNotBreakTheSessionCookie(t *testing.T) {
	a, s, m := newTestAuth(t)
	if w := newClient(t, a).do("POST", "/auth/password/signup", map[string]any{"email": "victim@x.com", "password": squatterPW, "name": strings.Repeat("A", 6000)}); w.Code != http.StatusOK {
		t.Fatalf("signup = %d", w.Code)
	}
	if _, err := s.UpsertExternalUser("scim:big", "big@x.com", strings.Repeat("é", 6000), true); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"victim@x.com", "big@x.com"} {
		c := magicLinkSignIn(t, a, m, email)
		if n := len(c.cookies["sweep_session"]); n == 0 || n > 3000 {
			t.Fatalf("%s: session cookie is %d bytes", email, n)
		}
	}
}

// Every /auth handler's body is capped, including the ones a library reads itself: the unauthenticated
// passkey sign-in handed its whole request to the WebAuthn library, which read all of it.
func TestAuthBodiesAreCapped(t *testing.T) {
	a, _, _ := newTestAuth(t)
	c := newClient(t, a)
	if w := c.do("POST", "/auth/webauthn/login/begin", nil); w.Code != http.StatusOK || len(c.cookies) == 0 {
		t.Fatalf("begin = %d %s", w.Code, w.Body.String())
	}
	body := &countingReader{r: bytes.NewReader(append([]byte(`{"id":"`), bytes.Repeat([]byte("A"), 8<<20)...))}
	r := httptest.NewRequest("POST", "/auth/webauthn/login/finish", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://app.example.com")
	for k, v := range c.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK || body.n > 2<<20 {
		t.Fatalf("finish = %d after reading %d bytes of an 8 MiB body", w.Code, body.n)
	}
}

type countingReader struct {
	r *bytes.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// A sign-in attempt for something that isn't an address is refused without an audit row.
func TestLoginWithAJunkEmailWritesNoAuditRow(t *testing.T) {
	a, s, _ := newTestAuth(t)
	junk := strings.Repeat("x", 4000)
	if code := newClient(t, a).loginCode(junk, "whatever-password-1"); code != http.StatusUnauthorized {
		t.Fatalf("junk email = %d, want 401", code)
	}
	if n, _ := s.RecentFailures(junk, time.Now().Add(-time.Hour)); n != 0 {
		t.Fatalf("%d audit rows written for a junk email", n)
	}
}
