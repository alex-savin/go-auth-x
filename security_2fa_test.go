package authx_test

// Regression tests for the 2026-11 security audit: what a stolen session can do with the second
// factor and step-up (C6), and throttling of factor checks (L1).

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// totpCode is what an authenticator app shows for secret at time t (RFC 6238: SHA-1, 6 digits, 30 s).
func totpCode(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		panic(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix())/30)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

// enrollTOTP enrolls TOTP over HTTP for a signed-in client that has already stepped up (if it must),
// returning the secret and the recovery codes.
func enrollTOTP(t *testing.T, c *client) (string, []any) {
	t.Helper()
	w := c.do("POST", "/auth/2fa/totp/begin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("totp/begin = %d %s", w.Code, w.Body.String())
	}
	secret := decode(t, w)["secret"].(string)
	w = c.do("POST", "/auth/2fa/totp/confirm", map[string]any{"code": totpCode(secret, time.Now())})
	if w.Code != http.StatusOK {
		t.Fatalf("totp/confirm = %d %s", w.Code, w.Body.String())
	}
	return secret, decode(t, w)["recoveryCodes"].([]any)
}

// stolen is a client holding only someone else's session cookie (and its own CSRF pair).
func stolen(c *client, victim *client) *client {
	thief := &client{t: c.t, h: c.h, cookies: map[string]string{"sweep_session": victim.cookies["sweep_session"], "sweep_csrf": "thief"}}
	return thief
}

// A stolen session of a password user can't add a factor to step up with — not TOTP, not a passkey.
func TestStolenSessionCantEnrollFactors(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "victim@x.com", "victim-password-1", true)
	victim := newClient(t, a)
	victim.login("victim@x.com", "victim-password-1")
	thief := stolen(victim, victim)

	for _, path := range []string{"/auth/2fa/totp/begin", "/auth/webauthn/register/begin"} {
		if w := thief.do("POST", path, nil); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "reauth_required") {
			t.Fatalf("%s without step-up = %d %s", path, w.Code, w.Body.String())
		}
	}
	// The owner, stepping up with their password, can.
	victim.reauth("victim-password-1")
	enrollTOTP(t, victim)
}

// Confirming an already enabled TOTP is refused: no code oracle, no fresh recovery codes, and the
// owner's recovery codes stay valid.
func TestTOTPConfirmRefusedOnceEnabled(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "victim@x.com", "victim-password-1", true)
	victim := newClient(t, a)
	victim.login("victim@x.com", "victim-password-1")
	victim.reauth("victim-password-1")
	secret, codes := enrollTOTP(t, victim)

	thief := stolen(victim, victim)
	if w := thief.do("POST", "/auth/2fa/totp/confirm", map[string]any{"code": totpCode(secret, time.Now().Add(30*time.Second))}); w.Code != http.StatusConflict {
		t.Fatalf("confirm on an enabled TOTP = %d, want 409", w.Code)
	}
	if w := victim.do("POST", "/auth/reauth", map[string]any{"code": codes[0]}); w.Code != http.StatusOK {
		t.Fatalf("the owner's recovery code must still work: %d", w.Code)
	}
}

// Guessing the code while an enrollment is pending is throttled per account, whatever the address.
func TestTOTPConfirmThrottled(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "user-password-12", true)
	c := newClient(t, a)
	c.login("u@x.com", "user-password-12")
	c.reauth("user-password-12")
	if w := c.do("POST", "/auth/2fa/totp/begin", nil); w.Code != http.StatusOK {
		t.Fatalf("begin = %d", w.Code)
	}
	for i := range 30 {
		w := c.doFromIP(fmt.Sprintf("203.0.113.%d", i), "POST", "/auth/2fa/totp/confirm", map[string]any{"code": "000000"})
		if w.Code == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatal("30 wrong codes from 30 addresses were never throttled")
}

// Disabling 2FA is throttled per account too, not only per address.
func TestTOTPDisableThrottledPerAccount(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "user-password-12", true)
	c := newClient(t, a)
	c.login("u@x.com", "user-password-12")
	c.reauth("user-password-12")
	enrollTOTP(t, c)
	for i := range 30 {
		if w := c.doFromIP(fmt.Sprintf("2001:db8:%x::1", i), "POST", "/auth/2fa/disable", map[string]any{"code": "000000"}); w.Code == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatal("30 wrong codes from 30 /64s were never throttled")
}

// A first password is a new factor: a TOTP user steps up before adding one, so a stolen session
// can't set a password and step up with it.
func TestFirstPasswordNeedsStepUpForTOTPUser(t *testing.T) {
	a, s, m := newTestAuth(t)
	seedUser(t, s, "u@x.com", "", true)
	c := newClient(t, a)
	c.do("POST", "/auth/email/request", map[string]any{"email": "u@x.com"})
	c.do("GET", "/auth/email/login?token="+tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/login").text)[1], nil)
	_, codes := enrollTOTP(t, c) // no factor yet: the session alone may add the first

	thief := stolen(c, c)
	if w := thief.do("POST", "/auth/api/account/password", map[string]any{"current": "", "new": "thief-password-123"}); w.Code != http.StatusForbidden {
		t.Fatalf("first password without step-up = %d, want 403", w.Code)
	}
	if w := c.do("POST", "/auth/reauth", map[string]any{"code": codes[0]}); w.Code != http.StatusOK {
		t.Fatalf("reauth = %d", w.Code)
	}
	if w := c.do("POST", "/auth/api/account/password", map[string]any{"current": "", "new": "owner-password-123"}); w.Code != http.StatusOK {
		t.Fatalf("first password after step-up = %d %s", w.Code, w.Body.String())
	}
}

// Checking the current password when changing it is throttled like /auth/reauth.
func TestChangePasswordCurrentCheckThrottled(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "user-password-12", true)
	c := newClient(t, a)
	c.login("u@x.com", "user-password-12")
	for i := range 30 {
		w := c.do("POST", "/auth/api/account/password", map[string]any{"current": fmt.Sprintf("guess-%02d-xxxxx", i), "new": "new-password-12345"})
		if w.Code == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatal("30 wrong current passwords were never throttled")
}

// doFromIP is client.do from a given remote address.
func (c *client) doFromIP(ip, method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	c.remote = ip
	defer func() { c.remote = "" }()
	return c.do(method, path, body)
}
