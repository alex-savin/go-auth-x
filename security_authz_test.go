package authx_test

// Regression tests for the second review (of v0.13.0): API-key scopes at the app's gate, key minting,
// the owner's account and admin keys, custom org roles, the last-owner guard, invites of a blocked
// manager, and the admin verbs' input handling and audit trail.

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// keyClient is a client that authenticates with an API key and holds no cookies.
func keyClient(t *testing.T, a *authx.Authenticator, key string) *client {
	c := newClient(t, a)
	c.bearer = key
	return c
}

// A global API key reaches the app's gated routes only with the app scope (or "*"). Scopes are
// deny-by-default there too: a key minted for a SCIM mount, or with no scopes at all, used to pass.
func TestAppGateRequiresTheAppScope(t *testing.T) {
	a, s, _ := newTestAuth(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gates := map[string]http.Handler{
		"GateHTTP":                     a.GateHTTP(inner),
		"GateHTTP + RequireGroupsHTTP": a.GateHTTP(a.RequireGroupsHTTP()(inner)),
		"RequireGroupsHTTP":            a.RequireGroupsHTTP()(inner),
	}
	hit := func(h http.Handler, key string) int {
		r := httptest.NewRequest("GET", "/api/private", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for name, scopes := range map[string][]string{"none": nil, "scim": {"scim"}, "admin": {"admin"}} {
		key := globalKey(t, s, "k"+name, scopes...)
		for gate, h := range gates {
			if code := hit(h, key); code == http.StatusOK {
				t.Fatalf("%s: a key with scopes %v passed", gate, scopes)
			}
		}
	}
	for name, scopes := range map[string][]string{"app": {authx.ScopeApp}, "root": {"*"}} {
		key := globalKey(t, s, "k"+name, scopes...)
		for gate, h := range gates {
			if code := hit(h, key); code != http.StatusOK {
				t.Fatalf("%s: a key with scopes %v = %d", gate, scopes, code)
			}
		}
	}
	// A key's groups count for RequireGroupsHTTP only with the app scope.
	raw := "axk_grouped_no_app_scope"
	h := sha256.Sum256([]byte(raw))
	if _, err := s.CreateAPIKey("grouped", []string{"analysts"}, []string{"scim"}, raw[:12], h[:], nil); err != nil {
		t.Fatal(err)
	}
	if code := hit(a.RequireGroupsHTTP("analysts")(inner), raw); code == http.StatusOK {
		t.Fatal("a key without the app scope satisfied a group gate")
	}
}

// A key mints no key wider or longer-lived than itself; the owner's session mints anything.
func TestAPIKeyMintsNoWiderOrLongerLivedKey(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-password-1", true)
	soon := time.Now().Add(time.Hour)
	raw := "axk_short_lived_admin_key"
	h := sha256.Sum256([]byte(raw))
	if _, err := s.CreateAPIKey("short", nil, []string{"admin"}, raw[:12], h[:], &soon); err != nil {
		t.Fatal(err)
	}
	k := keyClient(t, a, raw)
	if w := k.do("POST", "/auth/admin/apikeys", map[string]any{"name": "root", "scopes": []string{"*"}}); w.Code != http.StatusForbidden {
		t.Fatalf("an admin key minting a root key = %d, want 403", w.Code)
	}
	later := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	if w := k.do("POST", "/auth/admin/apikeys", map[string]any{"name": "long", "scopes": []string{"admin"}, "expiresAt": later}); w.Code != http.StatusForbidden {
		t.Fatalf("a key minting one that outlives it = %d, want 403", w.Code)
	}
	w := k.do("POST", "/auth/admin/apikeys", map[string]any{"name": "same", "scopes": []string{"admin"}})
	if w.Code != http.StatusOK {
		t.Fatalf("a key minting one like itself = %d %s", w.Code, w.Body.String())
	}
	minted, _ := decode(t, w)["apiKey"].(map[string]any)
	if minted["ExpiresAt"] == nil && minted["expiresAt"] == nil {
		t.Fatalf("a key minted by an expiring key must expire with it: %v", minted)
	}
	owner := newClient(t, a)
	owner.login("owner@example.com", "owner-password-1")
	if w := owner.do("POST", "/auth/admin/apikeys", map[string]any{"name": "root", "scopes": []string{"*"}}); w.Code != http.StatusOK {
		t.Fatalf("the owner minting a root key = %d %s", w.Code, w.Body.String())
	}
}

// An admin key can't ban, disable, delete, re-password or impersonate the owner: it would be the
// owner, and a leaked one could lock the owner out of the instance.
func TestAdminKeyCantActOnTheOwner(t *testing.T) {
	a, s, _ := newTestAuth(t)
	owner := seedUser(t, s, "owner@example.com", "owner-password-1", true)
	other := seedUser(t, s, "other@x.com", "other-password-1", true)
	k := keyClient(t, a, globalKey(t, s, "admin", "admin"))
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/disabled", map[string]any{"disabled": true}},
		{"POST", "/ban", map[string]any{"banned": true}},
		{"POST", "/password", map[string]any{"password": "Key-Chosen-Pw-55123"}},
		{"POST", "/impersonate", nil},
		{"DELETE", "", nil},
	} {
		if w := k.do(call.method, "/auth/admin/users/"+owner.ID+call.path, call.body); w.Code != http.StatusForbidden {
			t.Fatalf("an admin key: %s owner%s = %d %s, want 403", call.method, call.path, w.Code, w.Body.String())
		}
	}
	newClient(t, a).login("owner@example.com", "owner-password-1") // untouched
	// It still manages everyone else.
	if w := k.do("POST", "/auth/admin/users/"+other.ID+"/disabled", map[string]any{"disabled": true}); w.Code != http.StatusOK {
		t.Fatalf("an admin key disabling another user = %d %s", w.Code, w.Body.String())
	}
	// The owner's own session may act on the owner's account.
	oc := newClient(t, a)
	oc.login("owner@example.com", "owner-password-1")
	if w := oc.do("POST", "/auth/admin/users/"+owner.ID+"/password", map[string]any{"password": "A-Fresh-Passphrase-88231"}); w.Code != http.StatusOK {
		t.Fatalf("the owner's session on its own account = %d %s", w.Code, w.Body.String())
	}
}

// Ban and disable need their flag: a body that doesn't parse or leaves it out is refused — it used to
// read as "false" and lift the ban or re-enable the user. An unknown user is a 404.
func TestBanAndDisableNeedAnExplicitFlag(t *testing.T) {
	a, s, _ := newTestAuth(t)
	u := seedUser(t, s, "u@x.com", "users-password-1", true)
	_ = s.SetUserBan(u.ID, true, nil, "abuse")
	_ = s.SetUserDisabled(u.ID, true)
	k := keyClient(t, a, globalKey(t, s, "admin", "admin"))
	for _, body := range []any{map[string]any{"banned": "true"}, map[string]any{}, map[string]any{"reason": "x"}} {
		if w := k.do("POST", "/auth/admin/users/"+u.ID+"/ban", body); w.Code != http.StatusBadRequest {
			t.Fatalf("ban with %v = %d, want 400", body, w.Code)
		}
	}
	for _, body := range []any{map[string]any{"disabled": "yes"}, map[string]any{}} {
		if w := k.do("POST", "/auth/admin/users/"+u.ID+"/disabled", body); w.Code != http.StatusBadRequest {
			t.Fatalf("disabled with %v = %d, want 400", body, w.Code)
		}
	}
	if got, _ := s.UserByID(u.ID); !got.Banned || !got.Disabled {
		t.Fatalf("a malformed request changed the user: banned=%v disabled=%v", got.Banned, got.Disabled)
	}
	if w := k.do("POST", "/auth/admin/users/424242/ban", map[string]any{"banned": true}); w.Code != http.StatusNotFound {
		t.Fatalf("banning an unknown user = %d, want 404", w.Code)
	}
	if w := k.do("POST", "/auth/admin/users/424242/disabled", map[string]any{"disabled": true}); w.Code != http.StatusNotFound {
		t.Fatalf("disabling an unknown user = %d, want 404", w.Code)
	}
}

// The global group verbs add existing users to global groups only: a membership for an id nobody has
// yet would be inherited by the next account created with it, and an org's groups have their own
// verbs, which check org membership.
func TestGlobalGroupVerbsRefuseUnknownUsersAndOrgGroups(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	k := keyClient(t, a, globalKey(t, s, "admin", "admin"))
	g, _ := s.CreateGroup("admins", "")
	if w := k.do("POST", "/auth/admin/groups/"+g.ID+"/members/1", nil); w.Code != http.StatusNotFound {
		t.Fatalf("adding a user that doesn't exist = %d, want 404", w.Code)
	}
	_ = s.AddUserToGroup("1", g.ID) // the store refuses it too
	first := seedUser(t, s, "first@x.com", "first-password-1", true)
	if gs, _ := s.UserGroups(first.ID); len(gs) != 0 {
		t.Fatalf("a new account inherited groups: %v", gs)
	}
	org := seedOrg(t, s, "acme", nil)
	og, err := s.CreateOrgGroup(org.ID, "engineering", "")
	if err != nil {
		t.Fatal(err)
	}
	if w := k.do("POST", "/auth/admin/groups/"+og.ID+"/members/"+first.ID, nil); w.Code != http.StatusNotFound {
		t.Fatalf("the global verb on an org's group = %d, want 404", w.Code)
	}
	if gs, _ := s.UserGroups(first.ID); len(gs) != 0 {
		t.Fatalf("a non-member was put in an org's group: %v", gs)
	}
}

// auditSpy is a memory store that keeps what RecordAudit is told.
type auditSpy struct {
	*memory.Store
	mu   sync.Mutex
	rows []auditRow
}

type auditRow struct{ userID, method, action, detail string }

func (a *auditSpy) RecordAudit(userID, email, ip, method, action string, success bool, detail string) {
	a.mu.Lock()
	a.rows = append(a.rows, auditRow{userID, method, action, detail})
	a.mu.Unlock()
	a.Store.RecordAudit(userID, email, ip, method, action, success, detail)
}

// Every state-changing admin call leaves an audit row naming who made it.
func TestAdminVerbsAreAudited(t *testing.T) {
	spy := &auditSpy{Store: memory.New()}
	a, err := authx.New(context.Background(), authx.Config{
		SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", OwnerEmail: "owner@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(spy)
	a.SetDirectoryStore(spy.Store)
	a.SetSessionStore(spy.Store)
	a.SetLocalEnabled(true)
	u := seedUser(t, spy.Store, "u@x.com", "users-password-1", true)
	k := keyClient(t, a, globalKey(t, spy.Store, "admin", "admin"))
	k.do("POST", "/auth/admin/groups", map[string]any{"name": "analysts"})
	k.do("POST", "/auth/admin/users/"+u.ID+"/disabled", map[string]any{"disabled": true})
	k.do("GET", "/auth/admin/users", nil)
	var actions []string
	for _, e := range spy.rows {
		if e.method != "admin" {
			continue
		}
		if !strings.HasPrefix(e.detail, "apikey:") {
			t.Fatalf("admin audit row %q doesn't name its actor: %q", e.action, e.detail)
		}
		if strings.Contains(e.action, "/users/{id}") && e.userID != u.ID {
			t.Fatalf("admin audit row %q names user %q, want %q", e.action, e.userID, u.ID)
		}
		actions = append(actions, e.action)
	}
	joined := strings.Join(actions, " | ")
	if len(actions) != 2 || !strings.Contains(joined, "/auth/admin/groups") || !strings.Contains(joined, "/disabled") {
		t.Fatalf("admin audit rows = %q, want the two writes and not the read", joined)
	}
}

// An org admin grants "admin" and "member"; the app's own roles are an owner's to grant, by a role
// change or an invite — unless the app says otherwise (Config.OrgAdminMayGrant).
func TestOrgAdminGrantsOnlyBuiltInRoles(t *testing.T) {
	a, s, m := newOrgAuth(t)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	admin := seedUser(t, s, "a@x.com", "hunter2hunter2", true)
	member := seedUser(t, s, "m@x.com", "hunter2hunter2", true)
	org := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner, admin.ID: authx.OrgRoleAdmin, member.ID: authx.OrgRoleMember})
	ac, oc := newClient(t, a), newClient(t, a)
	ac.login("a@x.com", "hunter2hunter2")
	oc.login("o@x.com", "hunter2hunter2")

	for _, target := range []string{member.ID, admin.ID} {
		if w := ac.do("POST", "/auth/org/members/"+target, map[string]any{"role": "billing"}); w.Code != http.StatusForbidden {
			t.Fatalf("an admin granting a custom role to %s = %d, want 403", target, w.Code)
		}
	}
	if w := ac.do("POST", "/auth/org/invites", map[string]any{"email": "alt@x.com", "role": "billing"}); w.Code != http.StatusForbidden {
		t.Fatalf("an admin inviting with a custom role = %d, want 403", w.Code)
	}
	if w := ac.do("POST", "/auth/org/members/"+member.ID, map[string]any{"role": "admin"}); w.Code != http.StatusOK {
		t.Fatalf("an admin granting admin = %d %s", w.Code, w.Body.String())
	}
	if w := oc.do("POST", "/auth/org/members/"+member.ID, map[string]any{"role": "billing"}); w.Code != http.StatusOK {
		t.Fatalf("an owner granting a custom role = %d %s", w.Code, w.Body.String())
	}

	// An owner's custom-role invite stops granting when the owner is demoted to admin.
	if w := oc.do("POST", "/auth/org/invites", map[string]any{"email": "new@x.com", "role": "billing"}); w.Code != http.StatusOK {
		t.Fatalf("an owner inviting with a custom role = %d %s", w.Code, w.Body.String())
	}
	tok := tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/org/invite/accept").text)[1]
	second := seedUser(t, s, "second@x.com", "hunter2hunter2", true)
	_ = s.SetOrgMember(org.ID, second.ID, authx.OrgRoleOwner)
	_ = s.SetOrgMember(org.ID, owner.ID, authx.OrgRoleAdmin)
	seedUser(t, s, "new@x.com", "hunter2hunter2", true)
	nc := newClient(t, a)
	nc.login("new@x.com", "hunter2hunter2")
	nc.do("GET", "/auth/org/invite/accept?token="+tok, nil)
	if nu, _ := s.UserByEmail("new@x.com"); nu != nil {
		if role, err := s.OrgRole(org.ID, nu.ID); err == nil && role == "billing" {
			t.Fatal("an invite granted a custom role its inviter may no longer grant")
		}
	}
}

// A banned or disabled manager's pending invites grant nothing.
func TestBlockedInvitersInvitesGrantNothing(t *testing.T) {
	a, s, m := newOrgAuth(t)
	admin := seedUser(t, s, "a@x.com", "hunter2hunter2", true)
	org := seedOrg(t, s, "acme", map[string]string{admin.ID: authx.OrgRoleAdmin})
	ac := newClient(t, a)
	ac.login("a@x.com", "hunter2hunter2")
	if w := ac.do("POST", "/auth/org/invites", map[string]any{"email": "alt@x.com", "role": "admin"}); w.Code != http.StatusOK {
		t.Fatalf("invite = %d %s", w.Code, w.Body.String())
	}
	tok := tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/org/invite/accept").text)[1]
	_ = s.SetUserBan(admin.ID, true, nil, "abuse")
	alt := seedUser(t, s, "alt@x.com", "hunter2hunter2", true)
	c := newClient(t, a)
	c.login("alt@x.com", "hunter2hunter2")
	c.do("GET", "/auth/org/invite/accept?token="+tok, nil)
	if _, err := s.OrgRole(org.ID, alt.ID); err == nil {
		t.Fatal("a banned manager's invite still made a member")
	}
}

// The last owner of an org can't leave it ownerless by deleting their account, as they can't by
// leaving it.
func TestSoleOwnerCantDeleteTheirAccount(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	org := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner})
	c := newClient(t, a)
	c.login("o@x.com", "hunter2hunter2")
	c.reauth("hunter2hunter2")
	if w := c.do("DELETE", "/auth/api/account", nil); w.Code != http.StatusConflict {
		t.Fatalf("a sole owner deleting their account = %d %s, want 409", w.Code, w.Body.String())
	}
	second := seedUser(t, s, "second@x.com", "hunter2hunter2", true)
	_ = s.SetOrgMember(org.ID, second.ID, authx.OrgRoleOwner)
	if w := c.do("DELETE", "/auth/api/account", nil); w.Code != http.StatusOK {
		t.Fatalf("with another owner in place = %d %s", w.Code, w.Body.String())
	}
}

// A valid key that authorizes nothing doesn't switch CSRF off for the session cookie sent with it.
func TestInsufficientKeyDoesNotSkipCSRF(t *testing.T) {
	a, s, _ := newTestAuth(t)
	seedUser(t, s, "owner@example.com", "owner-password-1", true)
	oc := newClient(t, a)
	oc.login("owner@example.com", "owner-password-1")
	r := httptest.NewRequest("POST", "/auth/admin/groups", strings.NewReader(`{"name":"planted"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+globalKey(t, s, "scimonly", "scim"))
	r.AddCookie(&http.Cookie{Name: "sweep_session", Value: oc.cookies["sweep_session"]})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Fatal("a request with the owner's cookie and no CSRF token went through behind an unrelated key")
	}
	if _, err := s.GroupByName("planted"); err == nil {
		t.Fatal("the group was created")
	}
}
