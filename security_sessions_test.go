package authx_test

// Regression tests for the 2026-11 security audit: sessions outliving account changes (M1) and the
// client address behind proxies (M2).

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/alex-savin/go-auth-x/scim"
)

func (c *client) authenticated() bool {
	return decode(c.t, c.do("GET", "/auth/me", nil))["authenticated"] == true
}

// A password reset ends every session; a password change ends every session but the one making it.
func TestPasswordResetAndChangeEndOtherSessions(t *testing.T) {
	a, s, m := newTestAuth(t)
	seedUser(t, s, "u@x.com", "first-password-12", true)
	phone, laptop := newClient(t, a), newClient(t, a)
	phone.login("u@x.com", "first-password-12")
	laptop.login("u@x.com", "first-password-12")

	if w := laptop.do("POST", "/auth/api/account/password", map[string]any{"current": "first-password-12", "new": "second-password-12"}); w.Code != http.StatusOK {
		t.Fatalf("change = %d %s", w.Code, w.Body.String())
	}
	if !laptop.authenticated() || phone.authenticated() {
		t.Fatal("a password change must keep its own session and end the others")
	}

	newClient(t, a).do("POST", "/auth/password/reset/request", map[string]any{"email": "u@x.com"})
	tok := tokenRe.FindStringSubmatch(m.waitFor(t, "/reset?token=").text)[1]
	if w := newClient(t, a).do("POST", "/auth/password/reset/confirm", map[string]any{"token": tok, "password": "third-password-123"}); w.Code != http.StatusOK {
		t.Fatalf("reset = %d", w.Code)
	}
	if laptop.authenticated() {
		t.Fatal("a password reset must end every session")
	}
}

// Deprovisioning through SCIM ends the user's sessions at once.
func TestSCIMDeprovisionEndsSessions(t *testing.T) {
	a, s, _ := newTestAuth(t)
	u, err := s.UpsertExternalUser("scim:leaver", "leaver@x.com", "Leaver", true) // an account SCIM provisioned
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("leaver-password-1"), bcrypt.MinCost)
	_ = s.SetPasswordHash(u.ID, string(hash), "bcrypt")
	c := newClient(t, a)
	c.login("leaver@x.com", "leaver-password-1")
	raw := "axk_scim_key"
	h := sha256.Sum256([]byte(raw))
	_, _ = s.CreateAPIKey("idp", nil, []string{"scim"}, raw[:8], h[:], nil)
	srv := scim.NewServer(s, func(tok string) bool { return a.ValidateAPIKeyScope(tok, "scim") }).Handler()
	if w := scimDo(t, srv, raw, "PATCH", "/Users/"+u.ID, `{"Operations":[{"op":"replace","path":"active","value":false}]}`); w.Code != http.StatusOK {
		t.Fatalf("deprovision = %d", w.Code)
	}
	if c.authenticated() {
		t.Fatal("a deprovisioned user's session must end")
	}
}

// Group gates re-check directory groups live: removed from a group, a user loses what it gated.
func TestGroupRemovalTakesEffectAtOnce(t *testing.T) {
	a, s, _ := newTestAuth(t)
	u := seedUser(t, s, "u@x.com", "user-password-12", true)
	g, _ := s.CreateGroup("admins", "")
	_ = s.AddUserToGroup(u.ID, g.ID)
	c := newClient(t, a)
	c.login("u@x.com", "user-password-12")
	app := a.GateHTTP(a.RequireGroupsHTTP("admins")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})))
	hit := func() int {
		r := httptest.NewRequest("GET", "/admin", nil)
		r.AddCookie(&http.Cookie{Name: "sweep_session", Value: c.cookies["sweep_session"]})
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w.Code
	}
	if hit() != http.StatusOK {
		t.Fatal("a member must pass")
	}
	_ = s.RemoveUserFromGroup(u.ID, g.ID)
	if code := hit(); code != http.StatusForbidden {
		t.Fatalf("a removed member = %d, want 403", code)
	}
}

// Behind a trusted proxy the client is the nearest untrusted address across every X-Forwarded-For
// line, with any port stripped; an entry that isn't an address stops the walk at the proxy.
func TestClientIPAcrossForwardedForLines(t *testing.T) {
	a, _, _ := newTestAuth(t)
	req := func(lines ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.5:4444" // a trusted (private) proxy
		for _, l := range lines {
			r.Header.Add("X-Forwarded-For", l)
		}
		return r
	}
	for _, tc := range []struct {
		lines []string
		want  string
	}{
		{[]string{"6.6.6.6", "203.0.113.7"}, "203.0.113.7"}, // a client-written first line is not trusted
		{[]string{"6.6.6.6, 203.0.113.7"}, "203.0.113.7"},
		{[]string{"203.0.113.7:51234"}, "203.0.113.7"},     // proxies that add the port
		{[]string{"[2001:db8::7]:443"}, "2001:db8::7"},     // and the IPv6 form
		{[]string{"203.0.113.7, not-an-ip"}, "10.0.0.5"},   // garbage: stop at the proxy
		{[]string{"203.0.113.7, 10.0.0.9"}, "203.0.113.7"}, // skip trusted hops
	} {
		if got := a.ClientIP(req(tc.lines...)); got != tc.want {
			t.Errorf("X-Forwarded-For %q: ClientIP = %q, want %q", tc.lines, got, tc.want)
		}
	}
}
