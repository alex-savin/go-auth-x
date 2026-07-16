package authx_test

// v0.7 org-scoped resources: org groups (cookie exclusion + live gate), org-bound API keys
// (global-surface refusals), the org-scoped directory view, and per-customer SCIM isolation.

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/scim"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// orgScimKey mints an org-bound "scim" key directly in the store and returns the raw secret.
func orgScimKey(t *testing.T, s *memory.Store, orgID, name string) string {
	t.Helper()
	raw := "axk_" + name
	h := sha256.Sum256([]byte(raw))
	if _, err := s.CreateOrgAPIKey(orgID, name, nil, []string{"scim"}, raw, h[:], nil); err != nil {
		t.Fatal(err)
	}
	return raw
}

func scimDo(t *testing.T, h http.Handler, key, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// --- the org-scoped directory view, driven directly ---

func TestOrgScopedDirectoryView(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	_ = a
	owner := seedUser(t, s, "owner@a.com", "hunter2hunter2", true)
	outsider := seedUser(t, s, "outsider@x.com", "hunter2hunter2", true)
	orgA := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner})
	orgB := seedOrg(t, s, "globex", nil)

	viewA, err := authx.NewOrgScopedDirectory(s, s, orgA.ID)
	if err != nil {
		t.Fatal(err)
	}
	viewB, err := authx.NewOrgScopedDirectory(s, s, orgB.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Subject namespacing: the same SCIM userName provisioned by two orgs yields TWO accounts.
	ua, err := viewA.UpsertExternalUser("scim:jdoe", "jdoe@acme-corp.com", "J Doe", true)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := viewB.UpsertExternalUser("scim:jdoe", "jdoe@globex-corp.com", "J Doe", true)
	if err != nil {
		t.Fatal(err)
	}
	if ua.ID == ub.ID {
		t.Fatal("the same userName from two orgs must not resolve to one account")
	}
	if !strings.HasPrefix(ua.Sub, "scim:org"+orgA.ID+":") {
		t.Fatalf("provisioned sub must be org-namespaced, got %q", ua.Sub)
	}
	if role, rerr := s.OrgRole(orgA.ID, ua.ID); rerr != nil || role != authx.OrgRoleMember {
		t.Fatalf("provisioning must add org membership: %q, %v", role, rerr)
	}

	// Cross-tenant adoption guard: org B asserting an existing outside email is refused — the
	// underlying upsert would REBIND the account's subject (takeover); invites are the legal path.
	if _, err := viewB.UpsertExternalUser("scim:evil", "outsider@x.com", "Evil", true); !errors.Is(err, authx.ErrEmailConflict) {
		t.Fatalf("cross-tenant email adoption must be ErrEmailConflict, got %v", err)
	}
	if u, _ := s.UserByEmail("outsider@x.com"); u.Sub != outsider.Sub {
		t.Fatal("the outsider's subject must be untouched")
	}

	// Re-provision preserves an existing member's role (no demotion on SCIM re-push).
	if err := s.SetOrgMember(orgA.ID, ua.ID, authx.OrgRoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := viewA.UpsertExternalUser("scim:jdoe", "jdoe@acme-corp.com", "J Doe", true); err != nil {
		t.Fatal(err)
	}
	if role, _ := s.OrgRole(orgA.ID, ua.ID); role != authx.OrgRoleAdmin {
		t.Fatalf("re-provision must not demote, got %q", role)
	}

	// Deprovision = remove from THIS org, never the global account; owners are protected.
	if err := viewA.SetUserDisabled(ua.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OrgRole(orgA.ID, ua.ID); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatal("deprovision must remove the org membership")
	}
	if u, err := s.UserByEmail("jdoe@acme-corp.com"); err != nil || u.Disabled {
		t.Fatalf("deprovision must not disable the global account: %v", err)
	}
	if err := viewA.SetUserDisabled(ua.ID, true); err != nil {
		t.Fatalf("deprovisioning a non-member must be idempotent, got %v", err)
	}
	if err := viewA.SetUserDisabled(owner.ID, true); err == nil {
		t.Fatal("an org owner must not be deprovisionable via SCIM")
	}
	// Re-provision after deprovision (same namespaced sub) re-adds membership.
	if _, err := viewA.UpsertExternalUser("scim:jdoe", "jdoe@acme-corp.com", "J Doe", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OrgRole(orgA.ID, ua.ID); err != nil {
		t.Fatalf("re-provision must restore membership: %v", err)
	}

	// User reads are membership-gated; lists are org-confined.
	if _, err := viewB.UserByID(owner.ID); !errors.Is(err, authx.ErrNoUser) {
		t.Fatalf("another org's member must read as ErrNoUser, got %v", err)
	}
	us, _ := viewA.ListUsers()
	for _, u := range us {
		if u.Email == "jdoe@globex-corp.com" || u.Email == "outsider@x.com" {
			t.Fatalf("org A's list leaked %q", u.Email)
		}
	}

	// Groups: same name in both orgs; global verbs never see them; ops are org-confined.
	ga, err := viewA.CreateGroup("engineering", "via scim")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := viewB.CreateGroup("engineering", "via scim"); err != nil {
		t.Fatalf("two orgs must both be able to own 'engineering': %v", err)
	}
	if ga.OrgID != orgA.ID {
		t.Fatalf("view-created group must carry the org: %q", ga.OrgID)
	}
	if gs, _ := s.Groups(); len(gs) != 0 {
		t.Fatalf("global Groups() must not list org groups: %v", gs)
	}
	if _, err := s.GroupByName("engineering"); !errors.Is(err, authx.ErrNoGroup) {
		t.Fatalf("global GroupByName must not resolve org groups, got %v", err)
	}
	if err := viewA.AddUserToGroup(ub.ID, ga.ID); !errors.Is(err, authx.ErrNoUser) {
		t.Fatalf("grouping a non-member must be ErrNoUser, got %v", err)
	}
	if err := viewA.AddUserToGroup(ua.ID, ga.ID); err != nil {
		t.Fatal(err)
	}
	gb, _ := viewB.GroupByName("engineering")
	if err := viewA.DeleteGroup(gb.ID); !errors.Is(err, authx.ErrNoGroup) {
		t.Fatalf("another org's group must be invisible (ErrNoGroup), got %v", err)
	}

	// Removing an org member cascades their org-group membership (the OrgStore contract).
	if err := s.RemoveOrgMember(orgA.ID, ua.ID); err != nil {
		t.Fatal(err)
	}
	if members, _ := viewA.GroupMembers(ga.ID); len(members) != 0 {
		t.Fatalf("org-group membership must die with org membership: %v", members)
	}
}

// TestOrgScopedView_NoGlobalIdentityRebind is the regression for the cross-tenant takeover: a
// customer IdP must never rewrite the GLOBAL login identity of an account it did not provision
// (an invited "local:" member, or another org's / the global mount's account).
func TestOrgScopedView_NoGlobalIdentityRebind(t *testing.T) {
	_, s, _ := newOrgAuth(t)
	bob := seedUser(t, s, "bob@corp.com", "hunter2hunter2", true) // global "local:" account
	org := seedOrg(t, s, "acme", map[string]string{bob.ID: authx.OrgRoleMember})
	view, err := authx.NewOrgScopedDirectory(s, s, org.ID)
	if err != nil {
		t.Fatal(err)
	}

	// PUT-style update of an invited member to an UNOWNED address would, unguarded, rebind bob's
	// global email (verified, no mailbox proof) → password-reset/magic-link hijack. Must be refused.
	if _, err := view.UpsertExternalUser(bob.Sub, "attacker@evil.com", "Bob", true); !errors.Is(err, authx.ErrEmailConflict) {
		t.Fatalf("rebinding an invited member's global email must be refused, got %v", err)
	}
	if u, _ := s.UserByEmail("bob@corp.com"); u == nil || u.Sub != bob.Sub {
		t.Fatal("bob's global identity must be untouched")
	}
	if u, _ := s.UserByEmail("attacker@evil.com"); u != nil {
		t.Fatal("no account may now own the attacker address")
	}

	// The account this org's IdP DID provision is still updatable under its namespaced sub.
	prov, err := view.UpsertExternalUser("scim:jane", "jane@acme-corp.com", "Jane", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.UpsertExternalUser(prov.Sub, "jane@acme-corp.com", "Jane R", true); err != nil {
		t.Fatalf("an org-provisioned account must stay updatable: %v", err)
	}
}

// TestOrgBoundKey_RefusedByGlobalGate is the regression for the GateHTTP/authenticated hole: an
// org-bound key must not authenticate a global request gate.
func TestOrgBoundKey_RefusedByGlobalGate(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	org := seedOrg(t, s, "acme", nil)
	raw := orgScimKey(t, s, org.ID, "orgkey") // org-bound, scope "scim"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	bearer := func() *http.Request {
		r := httptest.NewRequest("GET", "/api/thing", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		return r
	}
	// GateHTTP must not admit the org key onto a protected app route.
	rec := httptest.NewRecorder()
	a.GateHTTP(inner).ServeHTTP(rec, bearer())
	if rec.Code == 200 {
		t.Fatalf("an org-bound key must not pass GateHTTP, got %d", rec.Code)
	}
	// RequireGroupsHTTP() with no groups (→ authenticated()) must reject it too.
	rec = httptest.NewRecorder()
	a.RequireGroupsHTTP()(inner).ServeHTTP(rec, bearer())
	if rec.Code == 200 {
		t.Fatalf("an org-bound key must not satisfy empty RequireGroupsHTTP, got %d", rec.Code)
	}
	// A GLOBAL key with a group still passes the group gate (control).
	graw, _, ghash := generateGlobalKey(t, s, "gkey", []string{"team"})
	_ = ghash
	rec = httptest.NewRecorder()
	gr := httptest.NewRequest("GET", "/api/thing", nil)
	gr.Header.Set("Authorization", "Bearer "+graw)
	a.RequireGroupsHTTP("team")(inner).ServeHTTP(rec, gr)
	if rec.Code != 200 {
		t.Fatalf("a global key in the group must still pass, got %d", rec.Code)
	}
}

// generateGlobalKey mints a global API key in the store and returns its raw secret.
func generateGlobalKey(t *testing.T, s *memory.Store, name string, groups []string) (raw, prefix string, hash []byte) {
	t.Helper()
	raw = "axk_" + name
	h := sha256.Sum256([]byte(raw))
	if _, err := s.CreateAPIKey(name, groups, []string{"*"}, raw, h[:], nil); err != nil {
		t.Fatal(err)
	}
	return raw, raw, h[:]
}

// --- per-customer SCIM, end-to-end over HTTP ---

func TestOrgScopedSCIM_HTTPIsolation(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	ownerA := seedUser(t, s, "owner@a.com", "hunter2hunter2", true)
	ownerB := seedUser(t, s, "owner@b.com", "hunter2hunter2", true)
	orgA := seedOrg(t, s, "acme", map[string]string{ownerA.ID: authx.OrgRoleOwner})
	orgB := seedOrg(t, s, "globex", map[string]string{ownerB.ID: authx.OrgRoleOwner})

	keyA := orgScimKey(t, s, orgA.ID, "scim-a")
	keyB := orgScimKey(t, s, orgB.ID, "scim-b")

	viewA, _ := authx.NewOrgScopedDirectory(s, s, orgA.ID)
	viewB, _ := authx.NewOrgScopedDirectory(s, s, orgB.ID)
	srvA := scim.NewServer(viewA, func(tok string) bool { return a.ValidateOrgAPIKeyScope(tok, "scim", orgA.ID) }).Handler()
	srvB := scim.NewServer(viewB, func(tok string) bool { return a.ValidateOrgAPIKeyScope(tok, "scim", orgB.ID) }).Handler()

	// The same userName provisioned into both orgs → two distinct accounts.
	if w := scimDo(t, srvA, keyA, "POST", "/Users", `{"userName":"jdoe","emails":[{"value":"jdoe@acme-corp.com"}]}`); w.Code != http.StatusCreated {
		t.Fatalf("provision into A = %d: %s", w.Code, w.Body.String())
	}
	if w := scimDo(t, srvB, keyB, "POST", "/Users", `{"userName":"jdoe","emails":[{"value":"jdoe@globex-corp.com"}]}`); w.Code != http.StatusCreated {
		t.Fatalf("provision into B = %d: %s", w.Code, w.Body.String())
	}
	uA, _ := s.UserByEmail("jdoe@acme-corp.com")
	uB, _ := s.UserByEmail("jdoe@globex-corp.com")
	if uA.ID == uB.ID {
		t.Fatal("cross-org userName collision")
	}

	// A key only opens ITS org's mount.
	if w := scimDo(t, srvA, keyB, "GET", "/Users", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("org B's key against org A's mount = %d, want 401", w.Code)
	}

	// Cross-tenant adoption via SCIM create → 409 uniqueness.
	if w := scimDo(t, srvB, keyB, "POST", "/Users", `{"userName":"evil","emails":[{"value":"owner@a.com"}]}`); w.Code != http.StatusConflict {
		t.Fatalf("cross-tenant email create = %d, want 409: %s", w.Code, w.Body.String())
	}

	// Listing is org-confined.
	if w := scimDo(t, srvA, keyA, "GET", "/Users", ""); !strings.Contains(w.Body.String(), "jdoe@acme-corp.com") ||
		strings.Contains(w.Body.String(), "globex-corp.com") || strings.Contains(w.Body.String(), "owner@b.com") {
		t.Fatalf("org A's /Users leaked or missed: %s", w.Body.String())
	}

	// Deprovision via PATCH active=false removes the membership, not the account.
	if w := scimDo(t, srvA, keyA, "PATCH", "/Users/"+uA.ID,
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`); w.Code >= 300 {
		t.Fatalf("PATCH deprovision = %d: %s", w.Code, w.Body.String())
	}
	if _, err := s.OrgRole(orgA.ID, uA.ID); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatal("PATCH active=false must remove the org membership")
	}
	if u, _ := s.UserByEmail("jdoe@acme-corp.com"); u == nil || u.Disabled {
		t.Fatal("the global account must survive an org deprovision")
	}

	// Deprovisioning an org OWNER via SCIM is refused with 403 (not a silent 200 that would fake
	// offboarding, nor a 500 an IdP retries forever). ownerA is org A's owner.
	if w := scimDo(t, srvA, keyA, "PATCH", "/Users/"+ownerA.ID,
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`); w.Code != http.StatusForbidden {
		t.Fatalf("PATCH-deprovision of an owner = %d, want 403: %s", w.Code, w.Body.String())
	}
	if w := scimDo(t, srvA, keyA, "DELETE", "/Users/"+ownerA.ID, ""); w.Code != http.StatusForbidden {
		t.Fatalf("DELETE-deprovision of an owner = %d, want 403", w.Code)
	}
	if role, err := s.OrgRole(orgA.ID, ownerA.ID); err != nil || role != authx.OrgRoleOwner {
		t.Fatalf("the owner must remain a member after a refused deprovision: %q, %v", role, err)
	}

	// Groups: both orgs own "engineering"; each mount lists only its own. A member list on a
	// group created with a FOREIGN member value silently drops the non-member (the view refuses).
	if w := scimDo(t, srvA, keyA, "POST", "/Groups", `{"displayName":"engineering","members":[{"value":"`+uB.ID+`"}]}`); w.Code != http.StatusCreated {
		t.Fatalf("group create A = %d: %s", w.Code, w.Body.String())
	}
	if w := scimDo(t, srvB, keyB, "POST", "/Groups", `{"displayName":"engineering"}`); w.Code != http.StatusCreated {
		t.Fatalf("group create B = %d: %s", w.Code, w.Body.String())
	}
	gA, err := s.OrgGroupByName(orgA.ID, "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if members, _ := s.GroupMembers(gA.ID); len(members) != 0 {
		t.Fatalf("a foreign user must not land in an org group: %v", members)
	}
	// Org B's mount can't reach org A's group: DELETE is a 404 (not a 500 retry-storm), and org A's
	// group survives.
	if w := scimDo(t, srvB, keyB, "DELETE", "/Groups/"+gA.ID, ""); w.Code != http.StatusNotFound {
		t.Fatalf("cross-org group DELETE = %d, want 404: %s", w.Code, w.Body.String())
	}
	if _, err := s.OrgGroupByName(orgA.ID, "engineering"); err != nil {
		t.Fatal("org A's group must survive a cross-org DELETE attempt")
	}
}

// --- org-bound API keys on the global surfaces ---

func TestOrgBoundAPIKeys_GlobalRefusals(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	seedUser(t, s, "owner@example.com", "hunter2hunter2", true)
	u := seedUser(t, s, "u@x.com", "hunter2hunter2", true)
	org := seedOrg(t, s, "acme", map[string]string{u.ID: authx.OrgRoleOwner})
	other := seedOrg(t, s, "globex", nil)

	// Admin REST mints an org-bound key (org by slug), carrying even the "admin" scope.
	admin := newClient(t, a)
	admin.login("owner@example.com", "hunter2hunter2")
	w := admin.do("POST", "/auth/admin/apikeys", map[string]any{"name": "a-key", "scopes": []string{"scim", "admin"}, "org": "acme"})
	if w.Code != 200 {
		t.Fatalf("create org key = %d: %s", w.Code, w.Body.String())
	}
	resp := decode(t, w)
	raw, _ := resp["key"].(string)
	info, _ := resp["apiKey"].(map[string]any)
	if info["orgId"] != org.ID {
		t.Fatalf("key must be org-bound: %v", info)
	}

	// Scope checks: its own org only; every global surface refuses it.
	if !a.ValidateOrgAPIKeyScope(raw, "scim", org.ID) {
		t.Fatal("org key must satisfy its own org's scope check")
	}
	if a.ValidateOrgAPIKeyScope(raw, "scim", other.ID) {
		t.Fatal("org key must not satisfy another org's scope check")
	}
	if a.ValidateAPIKeyScope(raw, "scim") {
		t.Fatal("org key must be refused by the GLOBAL scope check")
	}

	// adminGuard: org-bound + admin scope is still NOT global admin (403 insufficient_scope).
	r := httptest.NewRequest("GET", "/auth/admin/users", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org-bound admin key against global admin = %d, want 403", rec.Code)
	}

	// A global key with the same scopes still works everywhere (control).
	w = admin.do("POST", "/auth/admin/apikeys", map[string]any{"name": "g-key", "scopes": []string{"scim"}})
	global, _ := decode(t, w)["key"].(string)
	if !a.ValidateAPIKeyScope(global, "scim") || !a.ValidateOrgAPIKeyScope(global, "scim", org.ID) {
		t.Fatal("a global key must pass both the global and any org scope check")
	}
}

// --- org groups: cookie exclusion + live gate ---

func TestOrgGroups_CookieExclusionAndLiveGate(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	u := seedUser(t, s, "u@x.com", "hunter2hunter2", true)
	peer := seedUser(t, s, "p@x.com", "hunter2hunter2", true)
	org := seedOrg(t, s, "acme", map[string]string{u.ID: authx.OrgRoleMember, peer.ID: authx.OrgRoleMember})

	global, _ := s.CreateGroup("staff", "")
	if err := s.AddUserToGroup(u.ID, global.ID); err != nil {
		t.Fatal(err)
	}
	og, err := s.CreateOrgGroup(org.ID, "eng", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddUserToGroup(u.ID, og.ID); err != nil {
		t.Fatal(err)
	}

	// The cookie carries the GLOBAL group only — org group names collide across orgs.
	c := newClient(t, a)
	c.login("u@x.com", "hunter2hunter2")
	me := decode(t, c.do("GET", "/auth/me", nil))
	groups, _ := me["groups"].([]any)
	if len(groups) != 1 || groups[0] != "staff" {
		t.Fatalf("session groups must be global-only, got %v", me["groups"])
	}

	// RequireOrgGroupsHTTP gates on LIVE org-group membership within the active org.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	gate := a.GateHTTP(a.RequireOrgGroupsHTTP("eng")(inner))
	hit := func(cl *client) int {
		c2 := &client{t: t, h: gate, cookies: cl.cookies}
		return c2.do("GET", "/api/thing", nil).Code
	}
	if code := hit(c); code != 200 {
		t.Fatalf("org-group member = %d", code)
	}
	pc := newClient(t, a)
	pc.login("p@x.com", "hunter2hunter2")
	if code := hit(pc); code != http.StatusForbidden {
		t.Fatalf("non-group member = %d, want 403", code)
	}
	// Leaving the org strips its group access immediately (membership + group cascade, live check).
	if err := s.RemoveOrgMember(org.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if code := hit(c); code != http.StatusForbidden {
		t.Fatalf("removed member = %d, want 403", code)
	}
}

// --- admin org-group verbs ---

func TestAdminOrgGroupVerbs(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	seedUser(t, s, "owner@example.com", "hunter2hunter2", true)
	member := seedUser(t, s, "m@x.com", "hunter2hunter2", true)
	outsider := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	org := seedOrg(t, s, "acme", map[string]string{member.ID: authx.OrgRoleMember})

	c := newClient(t, a)
	c.login("owner@example.com", "hunter2hunter2")
	base := "/auth/admin/orgs/" + org.ID + "/groups"

	w := c.do("POST", base, map[string]any{"name": "eng"})
	if w.Code != 200 {
		t.Fatalf("create org group = %d: %s", w.Code, w.Body.String())
	}
	gid := decode(t, w)["id"].(string)
	if w := c.do("POST", base, map[string]any{"name": "eng"}); w.Code != http.StatusConflict {
		t.Fatalf("dup org group = %d, want 409", w.Code)
	}
	// Members: org members only; outsiders are a 409.
	if w := c.do("POST", base+"/"+gid+"/members/"+outsider.ID, nil); w.Code != http.StatusConflict {
		t.Fatalf("outsider into org group = %d, want 409", w.Code)
	}
	if w := c.do("POST", base+"/"+gid+"/members/"+member.ID, nil); w.Code != 200 {
		t.Fatalf("member into org group = %d", w.Code)
	}
	lst := decode(t, c.do("GET", base+"/"+gid+"/members", nil))
	if members, _ := lst["members"].([]any); len(members) != 1 {
		t.Fatalf("group members = %v", lst)
	}
	// A global group's ID under an org path is a 404 (no cross-namespace reach).
	gg, _ := s.CreateGroup("staff", "")
	if w := c.do("DELETE", base+"/"+gg.ID, nil); w.Code != http.StatusNotFound {
		t.Fatalf("global group via org path = %d, want 404", w.Code)
	}
	if w := c.do("DELETE", base+"/"+gid, nil); w.Code != 200 {
		t.Fatalf("delete org group = %d", w.Code)
	}
}

// --- store conformance: invites + v0.7 cascades (memory; gormstore mirrors in its own package) ---

func TestOrgStore_Memory_V07Conformance(t *testing.T) {
	s := memory.New()
	var store authx.OrgStore = s
	u, _ := s.CreateLocalUser("m@x.com", "M")
	o, _ := store.CreateOrg("acme", "Acme")

	// Invite lifecycle: create → peek (non-destructive) → consume (single-use) → gone.
	h1 := sha256.Sum256([]byte("tok1"))
	inv, err := store.CreateOrgInvite(o.ID, "new@x.com", "member", "m@x.com", h1[:], time.Now().Add(time.Hour))
	if err != nil || inv.ID == "" {
		t.Fatalf("CreateOrgInvite = %v, %v", inv, err)
	}
	if _, err := store.PeekOrgInvite(h1[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeekOrgInvite(h1[:]); err != nil {
		t.Fatal("peek must be non-destructive")
	}
	if got, err := store.ConsumeOrgInvite(h1[:]); err != nil || got.Role != "member" {
		t.Fatalf("consume = %v, %v", got, err)
	}
	if _, err := store.ConsumeOrgInvite(h1[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("second consume must be ErrTokenInvalid, got %v", err)
	}

	// Replacement: re-inviting the same email kills the previous pending token.
	h2 := sha256.Sum256([]byte("tok2"))
	h3 := sha256.Sum256([]byte("tok3"))
	_, _ = store.CreateOrgInvite(o.ID, "x@x.com", "member", "", h2[:], time.Now().Add(time.Hour))
	_, _ = store.CreateOrgInvite(o.ID, "x@x.com", "admin", "", h3[:], time.Now().Add(time.Hour))
	if _, err := store.PeekOrgInvite(h2[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("replaced invite must be dead, got %v", err)
	}
	if pending, _ := store.OrgInvites(o.ID); len(pending) != 1 || pending[0].Role != "admin" {
		t.Fatalf("pending = %+v", pending)
	}

	// Expired invites neither list nor redeem.
	h4 := sha256.Sum256([]byte("tok4"))
	_, _ = store.CreateOrgInvite(o.ID, "late@x.com", "member", "", h4[:], time.Now().Add(-time.Minute))
	if _, err := store.PeekOrgInvite(h4[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("expired invite must be ErrTokenInvalid, got %v", err)
	}

	// Revoke is idempotent and kills redemption.
	pending, _ := store.OrgInvites(o.ID)
	if err := store.RevokeOrgInvite(o.ID, pending[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeOrgInvite(o.ID, pending[0].ID); err != nil {
		t.Fatalf("revoke must be idempotent: %v", err)
	}
	if _, err := store.PeekOrgInvite(h3[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("revoked invite must be dead, got %v", err)
	}

	// DeleteOrg cascades groups, invites, and org-bound keys.
	_ = s.SetOrgMember(o.ID, u.ID, authx.OrgRoleMember)
	og, _ := s.CreateOrgGroup(o.ID, "eng", "")
	_ = s.AddUserToGroup(u.ID, og.ID)
	h5 := sha256.Sum256([]byte("tok5"))
	_, _ = store.CreateOrgInvite(o.ID, "y@x.com", "member", "", h5[:], time.Now().Add(time.Hour))
	kh := sha256.Sum256([]byte("axk_orgkey"))
	_, _ = s.CreateOrgAPIKey(o.ID, "k", nil, []string{"scim"}, "axk_orgk", kh[:], nil)
	if err := store.DeleteOrg(o.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OrgOfGroup(og.ID); !errors.Is(err, authx.ErrNoGroup) {
		t.Fatalf("org groups must die with the org, got %v", err)
	}
	if _, err := store.PeekOrgInvite(h5[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("org invites must die with the org, got %v", err)
	}
	if _, err := s.APIKeyByHash(kh[:]); !errors.Is(err, authx.ErrNoCredential) {
		t.Fatalf("org keys must die with the org, got %v", err)
	}

	// DeleteUser erases pending invites addressed to the user's email (GDPR parity).
	o2, _ := store.CreateOrg("globex", "Globex")
	victim, _ := s.CreateLocalUser("bye@x.com", "Bye")
	h6 := sha256.Sum256([]byte("tok6"))
	_, _ = store.CreateOrgInvite(o2.ID, "bye@x.com", "member", "", h6[:], time.Now().Add(time.Hour))
	_ = s.DeleteUser(victim.ID)
	if _, err := store.PeekOrgInvite(h6[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("invites to an erased user must be gone, got %v", err)
	}
}
