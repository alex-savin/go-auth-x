package authx_test

// End-to-end HTTP tests that drive the real Handler() (CSRF, cookies, step-up, the completeLogin
// funnel) against the in-memory reference store. This external test package can import store/memory
// (memory imports authx, not authx_test — no cycle), which the in-package tests cannot.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
	"golang.org/x/crypto/bcrypt"
)

// failRecord wraps the memory store but fails RecordSession, to prove a lost record fails the login.
type failRecord struct{ *memory.Store }

func (failRecord) RecordSession(authx.SessionRecord) error {
	return errors.New("simulated store write failure")
}

const testSecret = "0123456789abcdef0123456789abcdef"

// --- capturing mailer ---

type capMailer struct {
	mu   sync.Mutex
	msgs []capMsg
}

type capMsg struct{ to, subject, html, text string }

func (m *capMailer) Send(to, subject, html, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, capMsg{to, subject, html, text})
	return nil
}
func (m *capMailer) Configured() bool { return true }

// waitFor polls until a message whose text contains `needle` arrives (send paths are async).
func (m *capMailer) waitFor(t *testing.T, needle string) capMsg {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		for i := len(m.msgs) - 1; i >= 0; i-- {
			if strings.Contains(m.msgs[i].text, needle) || strings.Contains(m.msgs[i].subject, needle) {
				msg := m.msgs[i]
				m.mu.Unlock()
				return msg
			}
		}
		m.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no email containing %q arrived", needle)
	return capMsg{}
}

// --- harness ---

func newTestAuth(t *testing.T) (*authx.Authenticator, *memory.Store, *capMailer) {
	t.Helper()
	store := memory.New()
	mailer := &capMailer{}
	a, err := authx.New(context.Background(), authx.Config{
		SessionSecret: []byte(testSecret),
		AppURL:        "https://app.example.com",
		OwnerEmail:    "owner@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(store)
	a.SetDirectoryStore(store)
	a.SetTwoFactorStore(store)
	a.SetSessionStore(store)
	a.SetMailer(mailer)
	a.SetAuthorizer(store.Authorizer())
	a.SetLocalEnabled(true)
	return a, store, mailer
}

func seedUser(t *testing.T, s *memory.Store, email, pw string, verified bool) *authx.AuthUser {
	t.Helper()
	u, err := s.CreateLocalUser(email, "Name")
	if err != nil {
		t.Fatal(err)
	}
	if pw != "" {
		h, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		_ = s.SetPasswordHash(u.ID, string(h), "bcrypt")
	}
	if verified {
		_ = s.SetEmailVerified(u.ID, true)
	}
	return u
}

// client keeps a cookie jar and echoes the CSRF token + Origin like a real SPA.
type client struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]string
}

func newClient(t *testing.T, a *authx.Authenticator) *client {
	return &client{t: t, h: a.Handler(), cookies: map[string]string{}}
}

func (c *client) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for k, v := range c.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	if method != http.MethodGet {
		if tok := c.cookies["sweep_csrf"]; tok != "" {
			r.Header.Set("X-CSRF-Token", tok)
		}
		r.Header.Set("Origin", "https://app.example.com")
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	for _, sc := range w.Result().Cookies() {
		if sc.MaxAge < 0 || sc.Value == "" {
			delete(c.cookies, sc.Name)
		} else {
			c.cookies[sc.Name] = sc.Value
		}
	}
	return w
}

func (c *client) login(email, pw string) {
	c.t.Helper()
	if w := c.do("POST", "/auth/password/login", map[string]any{"email": email, "password": pw}); w.Code != 200 {
		c.t.Fatalf("login(%s) = %d: %s", email, w.Code, w.Body.String())
	}
}

func (c *client) reauth(pw string) {
	c.t.Helper()
	if w := c.do("POST", "/auth/reauth", map[string]any{"password": pw}); w.Code != 200 {
		c.t.Fatalf("reauth = %d: %s", w.Code, w.Body.String())
	}
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad JSON (%d): %s", w.Code, w.Body.String())
	}
	return m
}

var sixDigits = regexp.MustCompile(`\b(\d{6})\b`)
var tokenRe = regexp.MustCompile(`token=([A-Za-z0-9\-_]+)`)

// --- email OTP ---

func TestEmailOTP_HTTPHappyPath(t *testing.T) {
	a, s, mailer := newTestAuth(t)
	seedUser(t, s, "u@x.com", "", false)
	c := newClient(t, a)

	if w := c.do("POST", "/auth/email-otp/send", map[string]any{"email": "u@x.com"}); w.Code != 200 {
		t.Fatalf("send = %d", w.Code)
	}
	msg := mailer.waitFor(t, "sign-in code")
	code := sixDigits.FindStringSubmatch(msg.text)
	if code == nil {
		t.Fatalf("no 6-digit code in %q", msg.text)
	}
	w := c.do("POST", "/auth/email-otp/verify", map[string]any{"email": "u@x.com", "code": code[1]})
	if w.Code != 200 {
		t.Fatalf("verify = %d: %s", w.Code, w.Body.String())
	}
	if c.cookies["sweep_session"] == "" {
		t.Fatal("a session cookie must be set after OTP verify")
	}
	me := decode(t, c.do("GET", "/auth/me", nil))
	if me["authenticated"] != true || me["email"] != "u@x.com" {
		t.Fatalf("me = %v", me)
	}
}

func TestEmailOTP_WrongCodeThenExhausted(t *testing.T) {
	a, s, mailer := newTestAuth(t)
	seedUser(t, s, "u@x.com", "", false)
	c := newClient(t, a)
	_ = c.do("POST", "/auth/email-otp/send", map[string]any{"email": "u@x.com"})
	msg := mailer.waitFor(t, "sign-in code")
	code := sixDigits.FindStringSubmatch(msg.text)[1]

	for i := 0; i < 5; i++ { // maxOTPAttempts wrong guesses
		if w := c.do("POST", "/auth/email-otp/verify", map[string]any{"email": "u@x.com", "code": "000000x"}); w.Code == 200 {
			t.Fatal("a wrong code must not verify")
		}
	}
	// Even the correct code is dead now.
	if w := c.do("POST", "/auth/email-otp/verify", map[string]any{"email": "u@x.com", "code": code}); w.Code == 200 {
		t.Fatal("the code must be invalidated after the attempt cap")
	}
}

// --- account lifecycle: delete + change-email ---

func TestDeleteAccount_RequiresStepUp(t *testing.T) {
	a, s, _ := newTestAuth(t)
	u := seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	c.login("u@x.com", "correct-horse-9!")

	// Without a fresh step-up the delete is refused.
	if w := c.do("DELETE", "/auth/api/account", nil); w.Code != http.StatusForbidden {
		t.Fatalf("delete without step-up must be 403, got %d", w.Code)
	}
	c.reauth("correct-horse-9!")
	if w := c.do("DELETE", "/auth/api/account", nil); w.Code != 200 {
		t.Fatalf("delete after step-up = %d: %s", w.Code, w.Body.String())
	}
	if _, err := s.UserBySub(u.Sub); err != authx.ErrNoUser {
		t.Fatal("user must be gone after delete")
	}
}

func TestChangeEmail_VerifiedFlow(t *testing.T) {
	a, s, mailer := newTestAuth(t)
	u := seedUser(t, s, "old@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	c.login("old@x.com", "correct-horse-9!")
	c.reauth("correct-horse-9!")

	if w := c.do("POST", "/auth/api/account/email", map[string]any{"newEmail": "new@x.com"}); w.Code != 200 {
		t.Fatalf("change-email request = %d: %s", w.Code, w.Body.String())
	}
	// The new address is NOT written until the link is redeemed.
	if got, _ := s.UserBySub(u.Sub); got.Email != "old@x.com" {
		t.Fatalf("email changed before confirmation: %s", got.Email)
	}
	msg := mailer.waitFor(t, "/auth/email/change")
	tok := tokenRe.FindStringSubmatch(msg.html)
	if tok == nil {
		t.Fatalf("no token in confirm link: %s", msg.html)
	}
	if w := c.do("GET", "/auth/email/change?token="+tok[1], nil); w.Code != http.StatusFound {
		t.Fatalf("confirm = %d", w.Code)
	}
	if got, _ := s.UserBySub(u.Sub); got.Email != "new@x.com" || !got.EmailVerified {
		t.Fatalf("email not rebound: %+v", got)
	}
}

// --- OAuth unlink + passkey rename ---

func TestOAuthUnlinkAndPasskeyRename_HTTP(t *testing.T) {
	a, s, _ := newTestAuth(t)
	u := seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	_ = s.LinkOAuth(u.ID, "google", "g-sub", "u@x.com")
	_ = s.AddPasskey(u.ID, authx.Passkey{CredentialID: []byte("cred"), Name: "old"})
	c := newClient(t, a)
	c.login("u@x.com", "correct-horse-9!")

	// AccountInfo surfaces the linked provider.
	info := decode(t, c.do("GET", "/auth/api/account", nil))
	if oauth, _ := info["oauth"].([]any); len(oauth) != 1 || oauth[0] != "google" {
		t.Fatalf("account must list google, got %v", info["oauth"])
	}
	// Unlink google (password remains → allowed).
	if w := c.do("DELETE", "/auth/api/identities/google", nil); w.Code != 200 {
		t.Fatalf("unlink = %d: %s", w.Code, w.Body.String())
	}
	if ids, _ := s.OAuthIdentities(u.ID); len(ids) != 0 {
		t.Fatalf("google should be unlinked, got %v", ids)
	}
	// Unlinking again → 404.
	if w := c.do("DELETE", "/auth/api/identities/google", nil); w.Code != http.StatusNotFound {
		t.Fatalf("second unlink must 404, got %d", w.Code)
	}
	// Rename the passkey.
	pks, _ := s.Passkeys(u.ID)
	if w := c.do("POST", "/auth/api/passkeys/"+itoa(pks[0].ID), map[string]any{"name": "new"}); w.Code != 200 {
		t.Fatalf("rename = %d: %s", w.Code, w.Body.String())
	}
	pks, _ = s.Passkeys(u.ID)
	if pks[0].Name != "new" {
		t.Fatalf("rename failed: %q", pks[0].Name)
	}
}

// --- sessions: list + revoke-others ---

func TestSessionListAndRevokeOthers(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c1 := newClient(t, a)
	c1.login("u@x.com", "correct-horse-9!")
	c2 := newClient(t, a)
	c2.login("u@x.com", "correct-horse-9!")

	list := decode(t, c1.do("GET", "/auth/api/sessions", nil))
	if sess, _ := list["sessions"].([]any); len(sess) != 2 {
		t.Fatalf("want 2 sessions, got %v", list["sessions"])
	}
	if w := c1.do("POST", "/auth/api/sessions/revoke-others", nil); w.Code != 200 {
		t.Fatalf("revoke-others = %d", w.Code)
	}
	// c1 still works; c2 is now revoked (its /auth/me shows unauthenticated).
	if me := decode(t, c1.do("GET", "/auth/me", nil)); me["authenticated"] != true {
		t.Fatal("current session must survive revoke-others")
	}
	if me := decode(t, c2.do("GET", "/auth/me", nil)); me["authenticated"] != false {
		t.Fatal("the other session must be revoked")
	}
}

// --- admin verbs: create, ban, impersonate ---

func TestAdminCreateBanAndLoginGate(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-horse-9!", true)
	admin := newClient(t, a)
	admin.login("owner@example.com", "owner-horse-9!")

	// Create a user via the admin API.
	w := admin.do("POST", "/auth/admin/users", map[string]any{
		"email": "member@x.com", "name": "M", "password": "z9-strong-horse-battery!", "emailVerified": true,
	})
	if w.Code != 200 {
		t.Fatalf("admin create = %d: %s", w.Code, w.Body.String())
	}
	// The created user can log in.
	member := newClient(t, a)
	member.login("member@x.com", "z9-strong-horse-battery!")

	// Ban the member; a ban blocks a fresh login.
	mu, _ := s.UserByEmail("member@x.com")
	if w := admin.do("POST", "/auth/admin/users/"+itoa(mu.ID)+"/ban", map[string]any{"banned": true, "reason": "spam"}); w.Code != 200 {
		t.Fatalf("ban = %d: %s", w.Code, w.Body.String())
	}
	banned := newClient(t, a)
	if w := banned.do("POST", "/auth/password/login", map[string]any{"email": "member@x.com", "password": "z9-strong-horse-battery!"}); w.Code != http.StatusForbidden {
		t.Fatalf("banned login must be 403, got %d: %s", w.Code, w.Body.String())
	}
	// The ban also revoked the member's live session (session store is wired).
	if me := decode(t, member.do("GET", "/auth/me", nil)); me["authenticated"] != false {
		t.Fatal("ban must revoke the member's live session")
	}
}

func TestAdminImpersonation(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-horse-9!", true)
	target := seedUser(t, s, "target@x.com", "", true)
	admin := newClient(t, a)
	admin.login("owner@example.com", "owner-horse-9!")

	if w := admin.do("POST", "/auth/admin/users/"+itoa(target.ID)+"/impersonate", nil); w.Code != 200 {
		t.Fatalf("impersonate = %d: %s", w.Code, w.Body.String())
	}
	me := decode(t, admin.do("GET", "/auth/me", nil))
	if me["email"] != "target@x.com" || me["impersonatedBy"] == "" || me["impersonatedBy"] == nil {
		t.Fatalf("impersonation session wrong: %v", me)
	}
	// An impersonated session must NOT be able to act as admin.
	if w := admin.do("GET", "/auth/admin/users", nil); w.Code == 200 {
		t.Fatal("impersonated session must be refused admin access")
	}
	// Stop impersonating clears the session.
	if w := admin.do("POST", "/auth/api/stop-impersonating", nil); w.Code != 200 {
		t.Fatalf("stop-impersonating = %d", w.Code)
	}
	if admin.cookies["sweep_session"] != "" {
		t.Fatal("stop-impersonating must clear the session cookie")
	}
}

// --- CSRF trusted-origins + 429 ---

func TestCSRFRejectsMismatchedOrigin(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	c.login("u@x.com", "correct-horse-9!")

	// Craft a POST with a valid token cookie/header but a foreign Origin.
	r := httptest.NewRequest("POST", "/auth/api/account/password", bytes.NewReader([]byte(`{"current":"x","new":"y"}`)))
	for k, v := range c.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	r.Header.Set("X-CSRF-Token", c.cookies["sweep_csrf"])
	r.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a mismatched Origin must be rejected (403), got %d", w.Code)
	}
}

func TestRateLimit429WithRetryAfter(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	got429 := false
	for i := 0; i < 40; i++ {
		w := c.do("POST", "/auth/password/login", map[string]any{"email": "nobody@x.com", "password": "wrong"})
		if w.Code == http.StatusTooManyRequests {
			if ra := w.Header().Get("Retry-After"); ra == "" {
				t.Fatal("429 must carry a Retry-After header")
			}
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("the per-IP limiter must eventually return 429")
	}
}

func TestAuthConfigAdvertisesEmailOTP(t *testing.T) {
	a, _, _ := newTestAuth(t)
	c := newClient(t, a)
	cfg := decode(t, c.do("GET", "/auth/config", nil))
	methods, _ := cfg["methods"].(map[string]any)
	if methods["emailOtp"] != true {
		t.Fatalf("config must advertise emailOtp, got %v", cfg["methods"])
	}
}

type breachAll struct{}

func (breachAll) Pwned(context.Context, string) (bool, error) { return true, nil }

func TestSignupRejectsBreachedPassword(t *testing.T) {
	a, _, _ := newTestAuth(t)
	a.SetBreachChecker(breachAll{})
	c := newClient(t, a)
	w := c.do("POST", "/auth/password/signup", map[string]any{"email": "new@x.com", "password": "a-perfectly-fine-passphrase"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "breach") {
		t.Fatalf("a breached password must be refused at signup, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCSRFRequiredOnStateChange(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	c.login("u@x.com", "correct-horse-9!")

	// A state-changing POST WITHOUT the CSRF header must be refused, even with valid cookies.
	r := httptest.NewRequest("POST", "/auth/api/account/password", bytes.NewReader([]byte(`{"current":"x","new":"y"}`)))
	for k, v := range c.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	r.Header.Set("Origin", "https://app.example.com") // omit X-CSRF-Token
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token must be 403, got %d", w.Code)
	}
}

func TestChangeEmail_Conflict(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "old@x.com", "correct-horse-9!", true)
	seedUser(t, s, "taken@x.com", "", true)
	c := newClient(t, a)
	c.login("old@x.com", "correct-horse-9!")
	c.reauth("correct-horse-9!")
	if w := c.do("POST", "/auth/api/account/email", map[string]any{"newEmail": "taken@x.com"}); w.Code != http.StatusConflict {
		t.Fatalf("changing to a taken email must be 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminSetPasswordThenLogin(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-horse-9!", true)
	m := seedUser(t, s, "m@x.com", "old-passphrase-1", true)
	admin := newClient(t, a)
	admin.login("owner@example.com", "owner-horse-9!")

	if w := admin.do("POST", "/auth/admin/users/"+itoa(m.ID)+"/password", map[string]any{"password": "brand-new-passphrase-2"}); w.Code != 200 {
		t.Fatalf("admin set-password = %d: %s", w.Code, w.Body.String())
	}
	newClient(t, a).login("m@x.com", "brand-new-passphrase-2")
}

func TestAdminHardDelete(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-horse-9!", true)
	m := seedUser(t, s, "m@x.com", "", true)
	admin := newClient(t, a)
	admin.login("owner@example.com", "owner-horse-9!")
	if w := admin.do("DELETE", "/auth/admin/users/"+itoa(m.ID), nil); w.Code != 200 {
		t.Fatalf("admin delete = %d: %s", w.Code, w.Body.String())
	}
	if _, err := s.UserBySub(m.Sub); err != authx.ErrNoUser {
		t.Fatal("hard-deleted user must be gone")
	}
}

func TestAdminListAndRevokeUserSessions(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-horse-9!", true)
	m := seedUser(t, s, "m@x.com", "member-passphrase-1", true)
	member := newClient(t, a)
	member.login("m@x.com", "member-passphrase-1")
	admin := newClient(t, a)
	admin.login("owner@example.com", "owner-horse-9!")

	list := decode(t, admin.do("GET", "/auth/admin/users/"+itoa(m.ID)+"/sessions", nil))
	if sess, _ := list["sessions"].([]any); len(sess) != 1 {
		t.Fatalf("admin must see 1 member session, got %v", list["sessions"])
	}
	if w := admin.do("POST", "/auth/admin/users/"+itoa(m.ID)+"/sessions/revoke", nil); w.Code != 200 {
		t.Fatalf("admin revoke = %d", w.Code)
	}
	if me := decode(t, member.do("GET", "/auth/me", nil)); me["authenticated"] != false {
		t.Fatal("member session must be revoked by the admin")
	}
}

func TestSessionRevokeSpecific(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c1 := newClient(t, a)
	c1.login("u@x.com", "correct-horse-9!")
	c2 := newClient(t, a)
	c2.login("u@x.com", "correct-horse-9!")

	list := decode(t, c1.do("GET", "/auth/api/sessions", nil))
	var otherSID string
	for _, raw := range list["sessions"].([]any) {
		m := raw.(map[string]any)
		if m["current"] != true {
			otherSID = m["id"].(string)
		}
	}
	if otherSID == "" {
		t.Fatal("could not find the other session's id")
	}
	if w := c1.do("DELETE", "/auth/api/sessions/"+otherSID, nil); w.Code != 200 {
		t.Fatalf("revoke specific = %d", w.Code)
	}
	if me := decode(t, c2.do("GET", "/auth/me", nil)); me["authenticated"] != false {
		t.Fatal("the revoked session must be dead")
	}
	if me := decode(t, c1.do("GET", "/auth/me", nil)); me["authenticated"] != true {
		t.Fatal("the current session must survive")
	}
}

func TestStopImpersonatingWhenNotImpersonating(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	c.login("u@x.com", "correct-horse-9!")
	if w := c.do("POST", "/auth/api/stop-impersonating", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("stop-impersonating on a normal session must be 400, got %d", w.Code)
	}
}

func TestEmailOTP_UnknownUser(t *testing.T) {
	a, _, _ := newTestAuth(t)
	c := newClient(t, a)
	// Send is always a generic 200 (anti-enumeration), even for an unknown address.
	if w := c.do("POST", "/auth/email-otp/send", map[string]any{"email": "ghost@x.com"}); w.Code != 200 {
		t.Fatalf("send for unknown user must still be 200, got %d", w.Code)
	}
	// Verify with any code fails (no OTP was created).
	if w := c.do("POST", "/auth/email-otp/verify", map[string]any{"email": "ghost@x.com", "code": "123456"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("verify for unknown user must be 401, got %d", w.Code)
	}
}

func TestDeleteAccount_RevokesOtherDeviceSessions(t *testing.T) {
	// REGRESSION (#1): hard-deleting a user must revoke their sessions on OTHER devices, not un-revoke them.
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	laptop := newClient(t, a)
	laptop.login("u@x.com", "correct-horse-9!")
	phone := newClient(t, a)
	phone.login("u@x.com", "correct-horse-9!")

	laptop.reauth("correct-horse-9!")
	if w := laptop.do("DELETE", "/auth/api/account", nil); w.Code != 200 {
		t.Fatalf("delete = %d: %s", w.Code, w.Body.String())
	}
	if me := decode(t, phone.do("GET", "/auth/me", nil)); me["authenticated"] != false {
		t.Fatal("the other device's session must be revoked after account deletion")
	}
}

func TestPasswordReset_BadPasswordDoesNotBurnToken(t *testing.T) {
	// REGRESSION (#6): a policy-rejected password must not consume the single-use reset token.
	a, s, mailer := newTestAuth(t)
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	_ = c.do("POST", "/auth/password/reset/request", map[string]any{"email": "u@x.com"})
	msg := mailer.waitFor(t, "Reset your password")
	m := tokenRe.FindStringSubmatch(msg.html)
	if m == nil {
		t.Fatalf("no reset token in email: %s", msg.html)
	}
	token := m[1]
	if w := c.do("POST", "/auth/password/reset/confirm", map[string]any{"token": token, "password": "short"}); w.Code != http.StatusBadRequest {
		t.Fatalf("a bad password must be 400, got %d", w.Code)
	}
	// The SAME token must still work with an acceptable password.
	if w := c.do("POST", "/auth/password/reset/confirm", map[string]any{"token": token, "password": "brand-new-passphrase-2"}); w.Code != 200 {
		t.Fatalf("the token must survive the rejected attempt, got %d: %s", w.Code, w.Body.String())
	}
	newClient(t, a).login("u@x.com", "brand-new-passphrase-2")
}

func TestAdminCreateDuplicateEmailIs409(t *testing.T) {
	// REGRESSION (#3): a duplicate admin-create is a 409, not a 500 (store-parity of ErrEmailConflict).
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-horse-9!", true)
	seedUser(t, s, "dup@x.com", "", true)
	admin := newClient(t, a)
	admin.login("owner@example.com", "owner-horse-9!")
	if w := admin.do("POST", "/auth/admin/users", map[string]any{"email": "dup@x.com", "name": "D"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate admin-create must be 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginFailsWhenSessionRecordFails(t *testing.T) {
	// REGRESSION: a lost RecordSession write must FAIL the login, not mint a session that the fail-closed
	// revocation check would reject on the next request ("logged in, then instantly logged out").
	a, s, _ := newTestAuth(t)
	a.SetSessionStore(failRecord{s}) // record always errors
	seedUser(t, s, "u@x.com", "correct-horse-9!", true)
	c := newClient(t, a)
	w := c.do("POST", "/auth/password/login", map[string]any{"email": "u@x.com", "password": "correct-horse-9!"})
	if w.Code == http.StatusOK {
		t.Fatal("login must fail when the session record cannot be persisted")
	}
	if c.cookies["sweep_session"] != "" {
		t.Fatal("no session cookie may be set when recording failed")
	}
}

func TestDeleteAccount_PasswordlessSkipsStepUp(t *testing.T) {
	// REGRESSION (#4): a passwordless (social/OIDC-only) user has no step-up factor, so delete-account
	// must not demand one — otherwise they're permanently locked out of self-service deletion.
	a, s, mailer := newTestAuth(t)
	u := seedUser(t, s, "social@x.com", "", true) // no password, verified email
	c := newClient(t, a)
	_ = c.do("POST", "/auth/email-otp/send", map[string]any{"email": "social@x.com"})
	msg := mailer.waitFor(t, "sign-in code")
	code := sixDigits.FindStringSubmatch(msg.text)[1]
	if w := c.do("POST", "/auth/email-otp/verify", map[string]any{"email": "social@x.com", "code": code}); w.Code != http.StatusOK {
		t.Fatalf("otp login = %d", w.Code)
	}
	// No prior /auth/reauth — delete must still succeed for a passwordless account.
	if w := c.do("DELETE", "/auth/api/account", nil); w.Code != http.StatusOK {
		t.Fatalf("passwordless delete without step-up must succeed, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := s.UserBySub(u.Sub); err != authx.ErrNoUser {
		t.Fatal("user must be gone")
	}
}

// itoa avoids importing strconv just for the id path segments.
func itoa(u uint) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}
