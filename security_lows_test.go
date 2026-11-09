package authx_test

// Regression tests for the 2026-11 security audit's lower-severity findings: org-role races and id
// aliases, invites outliving their inviter, CSRF with a junk Bearer, the gate's path check, per-address
// budgets, and Secure cookies.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// racyOrgs pauses one SetOrgMember (made under the org lock) until a second request has read the
// paused target's role — the interleaving "a demotion holds the lock while the demoted owner's own
// request is in flight".
type racyOrgs struct {
	*memory.Store
	target       string
	armed, read  chan struct{}
	release      chan struct{}
	paused, seen bool
}

func (r *racyOrgs) SetOrgMember(orgID, userID, role string) error {
	if !r.paused && userID == r.target {
		r.paused = true
		close(r.armed)
		<-r.release
	}
	return r.Store.SetOrgMember(orgID, userID, role)
}

func (r *racyOrgs) OrgRole(orgID, userID string) (string, error) {
	role, err := r.Store.OrgRole(orgID, userID)
	if r.paused && !r.seen && userID == r.target {
		r.seen = true
		close(r.read)
	}
	return role, err
}

// An owner being demoted can't use a request already in flight (its role read before the demotion)
// to promote a puppet: the actor's role is re-read under the org lock.
func TestOrgActorRoleReadUnderLock(t *testing.T) {
	a, s, _ := newTestAuth(t)
	rs := &racyOrgs{Store: s, armed: make(chan struct{}), read: make(chan struct{}), release: make(chan struct{})}
	a.SetOrgStore(rs)
	victim := seedUser(t, s, "c@x.com", "hunter2hunter2", true)
	attacker := seedUser(t, s, "a@x.com", "hunter2hunter2", true)
	puppet := seedUser(t, s, "p@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{victim.ID: authx.OrgRoleOwner, attacker.ID: authx.OrgRoleOwner, puppet.ID: authx.OrgRoleMember})
	rs.target = attacker.ID
	vc, ac := newClient(t, a), newClient(t, a)
	vc.login("c@x.com", "hunter2hunter2")
	ac.login("a@x.com", "hunter2hunter2")

	done := make(chan int)
	go func() { done <- vc.do("POST", "/auth/org/members/"+attacker.ID, map[string]any{"role": "member"}).Code }()
	<-rs.armed
	atk := make(chan int)
	go func() { atk <- ac.do("POST", "/auth/org/members/"+puppet.ID, map[string]any{"role": "owner"}).Code }()
	<-rs.read
	close(rs.release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("demotion = %d", code)
	}
	if code := <-atk; code != http.StatusForbidden {
		t.Fatalf("the demoted owner's in-flight request = %d, want 403", code)
	}
	if role, _ := s.OrgRole(o.ID, puppet.ID); role != authx.OrgRoleMember {
		t.Fatalf("the puppet became %q", role)
	}
}

// Ids are canonical: "01" names no member, so it can't slip past the last-owner guard.
func TestOrgMemberIDsAreCanonical(t *testing.T) {
	a, s, _ := newTestAuth(t)
	a.SetOrgStore(s)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner})
	c := newClient(t, a)
	c.login("o@x.com", "hunter2hunter2")
	for _, alias := range []string{"0" + owner.ID, "00" + owner.ID} {
		if w := c.do("POST", "/auth/org/members/"+alias, map[string]any{"role": "member"}); w.Code == http.StatusOK {
			t.Fatalf("%q demoted the sole owner", alias)
		}
		if w := c.do("DELETE", "/auth/org/members/"+alias, nil); w.Code == http.StatusOK {
			t.Fatalf("%q removed the sole owner", alias)
		}
	}
	if role, _ := s.OrgRole(o.ID, owner.ID); role != authx.OrgRoleOwner {
		t.Fatalf("the sole owner is now %q", role)
	}
}

// An invite grants its role only while its inviter may still grant it.
func TestInviteRefusedAfterInviterLosesRole(t *testing.T) {
	a, s, m := newTestAuth(t)
	a.SetOrgStore(s)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	admin := seedUser(t, s, "adm@x.com", "hunter2hunter2", true)
	seedUser(t, s, "alt@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner, admin.ID: authx.OrgRoleAdmin})
	ac := newClient(t, a)
	ac.login("adm@x.com", "hunter2hunter2")
	if w := ac.do("POST", "/auth/org/invites", map[string]any{"email": "alt@x.com", "role": "admin"}); w.Code != http.StatusOK {
		t.Fatalf("invite = %d %s", w.Code, w.Body.String())
	}
	link := inviteLink(t, m, "invited you to join")
	if err := s.RemoveOrgMember(o.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	alt := newClient(t, a)
	alt.login("alt@x.com", "hunter2hunter2")
	alt.do("GET", link, nil)
	if _, err := s.OrgRole(o.ID, mustUser(t, s, "alt@x.com")); err == nil {
		t.Fatal("an invite from a removed admin must not grant membership")
	}
}

func mustUser(t *testing.T, s *memory.Store, email string) string {
	t.Helper()
	u, err := s.UserByEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// An Authorization header that isn't a valid key doesn't switch CSRF off for a cookie-authenticated
// request.
func TestJunkBearerDoesNotSkipCSRF(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-password-1", true)
	c := newClient(t, a)
	c.login("owner@example.com", "owner-password-1")
	r := httptest.NewRequest("POST", "/auth/admin/apikeys", strings.NewReader(`{"name":"pwned","scopes":["admin"]}`))
	r.AddCookie(&http.Cookie{Name: "sweep_session", Value: c.cookies["sweep_session"]})
	r.Header.Set("Origin", "https://evil.test")
	r.Header.Set("Authorization", "Bearer not-a-real-key")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a cross-site request with a junk Bearer = %d, want 403", w.Code)
	}
}

// The gate decides "public" on the cleaned path: /_next/../secret is /secret.
func TestGateDecidesOnCleanPath(t *testing.T) {
	a, _, _ := newTestAuth(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.txt"), []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	gated := a.GateHTTP(http.FileServer(http.Dir(dir)))
	for _, p := range []string{"/_next/../report.txt", "/auth/../report.txt", "/auth/%2e%2e/report.txt"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path, r.RequestURI = strings.ReplaceAll(p, "%2e", "."), p
		w := httptest.NewRecorder()
		gated.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "TOP-SECRET") {
			t.Fatalf("%s served a gated file without a session", p)
		}
	}
}

// Checking email codes has a per-address budget across codes (a fresh code used to reset the guesses).
func TestEmailOTPVerifyBudgetPerAddress(t *testing.T) {
	a, s, m := newTestAuth(t)
	seedUser(t, s, "v@x.com", "", true)
	c := newClient(t, a)
	for i := 0; i < 30; i++ {
		if i%5 == 0 { // a fresh code every five guesses, as an attacker would
			c.doFromIP(fmt.Sprintf("203.0.113.%d", i), "POST", "/auth/email-otp/send", map[string]any{"email": "v@x.com"})
			m.waitFor(t, "sign-in code")
		}
		if w := c.doFromIP(fmt.Sprintf("198.51.100.%d", i), "POST", "/auth/email-otp/verify", map[string]any{"email": "v@x.com", "code": "000000"}); w.Code == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatal("30 wrong codes against one address were never throttled")
}

// Signup can't flood one address with mail (the answer stays the same).
func TestSignupMailLimitedPerAddress(t *testing.T) {
	a, _, m := newTestAuth(t)
	c := newClient(t, a)
	for i := 0; i < 15; i++ {
		if w := c.doFromIP(fmt.Sprintf("203.0.113.%d", i), "POST", "/auth/password/signup", map[string]any{"email": "target@x.com", "password": fmt.Sprintf("bomb-password-%02d", i)}); w.Code != http.StatusOK {
			t.Fatalf("signup %d = %d", i, w.Code)
		}
	}
	m.waitFor(t, "Confirm your email")
	m.mu.Lock()
	n := len(m.msgs)
	m.mu.Unlock()
	if n > 10 {
		t.Fatalf("15 signups sent %d emails to one address, want at most 10", n)
	}
}

// An https app's cookies are Secure even when the request reached it as plain http (a proxy that
// doesn't send X-Forwarded-Proto).
func TestSecureCookiesForHTTPSApp(t *testing.T) {
	a, s, _ := newTestAuth(t) // AppURL https://app.example.com
	seedUser(t, s, "u@x.com", "user-password-12", true)
	r := httptest.NewRequest("POST", "http://app.example.com/auth/password/login", strings.NewReader(`{"email":"u@x.com","password":"user-password-12"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "sweep_session" && !ck.Secure {
			t.Fatal("the session cookie of an https app must be Secure")
		}
	}
}
