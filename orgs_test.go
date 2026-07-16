package authx_test

// End-to-end tests for the organization layer: store conformance (memory), the active-org session
// claim, switching, RequireOrgHTTP's live re-verification, the invite flow, self-service member
// management (incl. the last-owner guard), and the admin org verbs.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// newOrgAuth is newTestAuth plus the org store — kept separate so the org layer stays off in every
// other test file (proving nil OrgStore = zero behavior change).
func newOrgAuth(t *testing.T) (*authx.Authenticator, *memory.Store, *capMailer) {
	t.Helper()
	a, s, m := newTestAuth(t)
	a.SetOrgStore(s)
	return a, s, m
}

func seedOrg(t *testing.T, s *memory.Store, slug string, members map[string]string) *authx.Org {
	t.Helper()
	o, err := s.CreateOrg(slug, strings.ToUpper(slug))
	if err != nil {
		t.Fatal(err)
	}
	for uid, role := range members {
		if err := s.SetOrgMember(o.ID, uid, role); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

// --- store conformance (memory; gormstore has the same suite over sqlite) ---

func TestOrgStore_Memory_Conformance(t *testing.T) {
	s := memory.New()
	var store authx.OrgStore = s

	o, err := store.CreateOrg("acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateOrg("acme", "Dup"); err == nil {
		t.Fatal("a duplicate slug must be refused")
	}
	if got, err := store.OrgBySlug("acme"); err != nil || got.ID != o.ID {
		t.Fatalf("OrgBySlug = %v, %v", got, err)
	}
	if _, err := store.OrgByID("999"); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("missing org must be ErrNoOrg, got %v", err)
	}
	if _, err := store.OrgByID("not-a-number"); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("a malformed opaque ID is an ID that can't exist → ErrNoOrg, got %v", err)
	}
	if err := store.RenameOrg(o.ID, "Acme Inc"); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.OrgByID(o.ID); got.Name != "Acme Inc" {
		t.Fatalf("rename not applied: %q", got.Name)
	}

	u, _ := s.CreateLocalUser("m@x.com", "M")
	if err := store.SetOrgMember("999", u.ID, authx.OrgRoleMember); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("membership in a missing org must be ErrNoOrg, got %v", err)
	}
	if err := store.SetOrgMember(o.ID, u.ID, authx.OrgRoleMember); err != nil {
		t.Fatal(err)
	}
	if role, err := store.OrgRole(o.ID, u.ID); err != nil || role != authx.OrgRoleMember {
		t.Fatalf("OrgRole = %q, %v", role, err)
	}
	// SetOrgMember is an UPSERT: second call updates the role, and re-setting the SAME role is
	// idempotent (no unique-index trip).
	if err := store.SetOrgMember(o.ID, u.ID, authx.OrgRoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOrgMember(o.ID, u.ID, authx.OrgRoleOwner); err != nil {
		t.Fatalf("same-role re-set must be idempotent, got %v", err)
	}
	if role, _ := store.OrgRole(o.ID, u.ID); role != authx.OrgRoleOwner {
		t.Fatalf("upsert must update the role, got %q", role)
	}
	// A membership for a nonexistent user is refused — a dangling row would be inherited by the
	// future user assigned that ID.
	if err := store.SetOrgMember(o.ID, "4242", authx.OrgRoleOwner); !errors.Is(err, authx.ErrNoUser) {
		t.Fatalf("membership for a missing user must be ErrNoUser, got %v", err)
	}
	if _, err := store.OrgRole(o.ID, "4242"); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatalf("non-member must be ErrNotOrgMember, got %v", err)
	}
	if ms, _ := store.UserOrgs(u.ID); len(ms) != 1 || ms[0].Org.ID != o.ID || ms[0].Role != authx.OrgRoleOwner {
		t.Fatalf("UserOrgs = %+v", ms)
	}
	if mem, _ := store.OrgMembers(o.ID); len(mem) != 1 || mem[0].User.ID != u.ID {
		t.Fatalf("OrgMembers = %+v", mem)
	}
	if err := store.RemoveOrgMember(o.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveOrgMember(o.ID, u.ID); err != nil {
		t.Fatalf("RemoveOrgMember must be idempotent, got %v", err)
	}

	// A hard user delete cascades org memberships.
	_ = store.SetOrgMember(o.ID, u.ID, authx.OrgRoleMember)
	_ = s.DeleteUser(u.ID)
	if _, err := store.OrgRole(o.ID, u.ID); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatalf("DeleteUser must cascade org membership, got %v", err)
	}

	// DeleteOrg cascades memberships and is idempotent.
	if err := store.DeleteOrg(o.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteOrg(o.ID); err != nil {
		t.Fatalf("DeleteOrg must be idempotent, got %v", err)
	}
	if _, err := store.OrgByID(o.ID); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("deleted org must be gone, got %v", err)
	}
}

// --- active-org claim at login ---

func TestOrgLogin_SoleMembershipBecomesActive(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	u := seedUser(t, s, "u@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{u.ID: authx.OrgRoleOwner})

	c := newClient(t, a)
	c.login("u@x.com", "hunter2hunter2")
	me := decode(t, c.do("GET", "/auth/me", nil))
	org, _ := me["org"].(map[string]any)
	if org == nil || org["id"] != o.ID || me["orgRole"] != authx.OrgRoleOwner {
		t.Fatalf("sole membership must become the active org: %v", me)
	}
	if orgs, _ := me["orgs"].([]any); len(orgs) != 1 {
		t.Fatalf("orgs = %v", me["orgs"])
	}
}

func TestOrgLogin_MultipleMembershipsMeansNoActiveOrg(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	u := seedUser(t, s, "u@x.com", "hunter2hunter2", true)
	seedOrg(t, s, "acme", map[string]string{u.ID: authx.OrgRoleOwner})
	seedOrg(t, s, "globex", map[string]string{u.ID: authx.OrgRoleMember})

	c := newClient(t, a)
	c.login("u@x.com", "hunter2hunter2")
	me := decode(t, c.do("GET", "/auth/me", nil))
	if me["org"] != nil {
		t.Fatalf("several memberships must not guess an active org: %v", me["org"])
	}
	if orgs, _ := me["orgs"].([]any); len(orgs) != 2 {
		t.Fatalf("both memberships must be listed: %v", me["orgs"])
	}
}

// --- switching ---

// cookieClaims decodes a JWT cookie's payload (unverified — test-side inspection only).
func cookieClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func TestOrgSwitch(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	u := seedUser(t, s, "u@x.com", "hunter2hunter2", true)
	acme := seedOrg(t, s, "acme", map[string]string{u.ID: authx.OrgRoleAdmin})
	seedOrg(t, s, "globex", map[string]string{u.ID: authx.OrgRoleMember})
	stranger := seedOrg(t, s, "stranger", nil)

	c := newClient(t, a)
	c.login("u@x.com", "hunter2hunter2")
	before := cookieClaims(t, c.cookies["sweep_session"])

	// Switch by slug.
	w := c.do("POST", "/auth/org/switch", map[string]any{"org": "acme"})
	if w.Code != 200 {
		t.Fatalf("switch = %d: %s", w.Code, w.Body.String())
	}
	me := decode(t, c.do("GET", "/auth/me", nil))
	if org, _ := me["org"].(map[string]any); org == nil || org["slug"] != "acme" || me["orgRole"] != authx.OrgRoleAdmin {
		t.Fatalf("active org after switch: %v", me)
	}

	// The re-mint preserves the SID (server-side revocation continuity) and does NOT extend the session.
	after := cookieClaims(t, c.cookies["sweep_session"])
	if before["sid"] != after["sid"] {
		t.Fatalf("switch must keep the SID: %v -> %v", before["sid"], after["sid"])
	}
	expB, _ := before["exp"].(float64)
	expA, _ := after["exp"].(float64)
	if expA > expB+2 {
		t.Fatalf("switch must not extend the session: %v -> %v", expB, expA)
	}

	// Switch by ID.
	if w := c.do("POST", "/auth/org/switch", map[string]any{"org": acme.ID}); w.Code != 200 {
		t.Fatalf("switch by id = %d", w.Code)
	}

	// The explicit slug field resolves by slug ONLY — immune to an org whose opaque ID collides
	// with an all-digit slug.
	if w := c.do("POST", "/auth/org/switch", map[string]any{"slug": "globex"}); w.Code != 200 {
		t.Fatalf("switch by slug field = %d", w.Code)
	}
	me = decode(t, c.do("GET", "/auth/me", nil))
	if org, _ := me["org"].(map[string]any); org == nil || org["slug"] != "globex" {
		t.Fatalf("active org after slug-field switch: %v", me["org"])
	}
	if w := c.do("POST", "/auth/org/switch", map[string]any{"slug": acme.ID}); w.Code != http.StatusForbidden {
		t.Fatalf("slug field must NOT fall back to ID resolution: %d", w.Code)
	}

	// A non-member org and a nonexistent org are the SAME 403 (no existence oracle).
	w1 := c.do("POST", "/auth/org/switch", map[string]any{"org": stranger.Slug})
	w2 := c.do("POST", "/auth/org/switch", map[string]any{"org": "no-such-org"})
	if w1.Code != http.StatusForbidden || w2.Code != http.StatusForbidden {
		t.Fatalf("switch to non-member/missing org = %d/%d, want 403/403", w1.Code, w2.Code)
	}
	if b1, b2 := w1.Body.String(), w2.Body.String(); b1 != b2 {
		t.Fatalf("non-member vs missing must be indistinguishable: %q vs %q", b1, b2)
	}

	// Clearing the active org.
	if w := c.do("POST", "/auth/org/switch", map[string]any{"org": ""}); w.Code != 200 {
		t.Fatalf("clear = %d", w.Code)
	}
	me = decode(t, c.do("GET", "/auth/me", nil))
	if me["org"] != nil {
		t.Fatalf("active org must be cleared: %v", me["org"])
	}
}

// --- RequireOrgHTTP ---

func TestRequireOrgHTTP_LiveReverification(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	member := seedUser(t, s, "m@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner, member.ID: authx.OrgRoleMember})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	ownerGate := a.GateHTTP(a.RequireOrgHTTP(authx.OrgRoleOwner)(inner))
	anyMember := a.GateHTTP(a.RequireOrgHTTP()(inner))

	login := func(email string) *client {
		c := newClient(t, a)
		c.login(email, "hunter2hunter2")
		return c
	}
	hit := func(c *client, h http.Handler) int {
		c2 := &client{t: t, h: h, cookies: c.cookies}
		return c2.do("GET", "/api/thing", nil).Code
	}

	oc, mc := login("o@x.com"), login("m@x.com")
	if code := hit(oc, ownerGate); code != 200 {
		t.Fatalf("owner through owner-gate = %d", code)
	}
	if code := hit(mc, ownerGate); code != http.StatusForbidden {
		t.Fatalf("member through owner-gate = %d, want 403", code)
	}
	if code := hit(mc, anyMember); code != 200 {
		t.Fatalf("member through member-gate = %d", code)
	}

	// Live re-verification: removing the member closes the gate IMMEDIATELY, same cookie.
	if err := s.RemoveOrgMember(o.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if code := hit(mc, anyMember); code != http.StatusForbidden {
		t.Fatalf("a removed member must be refused with their old cookie, got %d", code)
	}

	// No active org (fresh user with no memberships) → 403.
	seedUser(t, s, "n@x.com", "hunter2hunter2", true)
	nc := login("n@x.com")
	if code := hit(nc, anyMember); code != http.StatusForbidden {
		t.Fatalf("no active org must be 403, got %d", code)
	}
}

// --- invites ---

var linkRe = regexp.MustCompile(`https://app\.example\.com(/auth/org/invite/accept\?\S+)`)

func inviteLink(t *testing.T, m *capMailer, needle string) string {
	t.Helper()
	msg := m.waitFor(t, needle)
	match := linkRe.FindStringSubmatch(msg.text)
	if match == nil {
		t.Fatalf("no accept link in %q", msg.text)
	}
	return match[1]
}

func TestOrgInvite_EndToEnd(t *testing.T) {
	a, s, mailer := newOrgAuth(t)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner})

	oc := newClient(t, a)
	oc.login("o@x.com", "hunter2hunter2") // sole membership → acme is active

	if w := oc.do("POST", "/auth/org/invites", map[string]any{"email": "new@x.com", "role": "member"}); w.Code != 200 {
		t.Fatalf("invite = %d: %s", w.Code, w.Body.String())
	}
	link := inviteLink(t, mailer, "invited you to join")

	// Unauthenticated click bounces to login with the accept URL as next.
	anon := newClient(t, a)
	w := anon.do("GET", link, nil)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/login?next=") {
		t.Fatalf("anonymous accept = %d -> %q", w.Code, w.Header().Get("Location"))
	}

	// The invitee follows the REAL reference funnel: sign up, confirm the email via the emailed
	// link (which also signs them in), then accept — membership granted and the session lands IN
	// the new org.
	ic := newClient(t, a)
	if w := ic.do("POST", "/auth/password/signup", map[string]any{"email": "new@x.com", "password": "hunter2hunter2"}); w.Code != 200 {
		t.Fatalf("signup = %d: %s", w.Code, w.Body.String())
	}
	confirm := mailer.waitFor(t, "Confirm your email")
	tok := tokenRe.FindStringSubmatch(confirm.text)
	if tok == nil {
		t.Fatalf("no token in confirm mail: %q", confirm.text)
	}
	if w := ic.do("GET", "/auth/email/verify?token="+tok[1], nil); ic.cookies["sweep_session"] == "" {
		t.Fatalf("verify-link login failed: %d -> %q", w.Code, w.Header().Get("Location"))
	}
	if w := ic.do("GET", link, nil); w.Code != http.StatusFound || strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatalf("accept = %d -> %q", w.Code, w.Header().Get("Location"))
	}
	invitee, err := s.UserByEmail("new@x.com")
	if err != nil {
		t.Fatal(err)
	}
	if role, rerr := s.OrgRole(o.ID, invitee.ID); rerr != nil || role != authx.OrgRoleMember {
		t.Fatalf("membership after accept = %q, %v", role, rerr)
	}
	me := decode(t, ic.do("GET", "/auth/me", nil))
	if org, _ := me["org"].(map[string]any); org == nil || org["id"] != o.ID {
		t.Fatalf("accept must activate the joined org: %v", me["org"])
	}

	// Single-use: a second redemption fails.
	if w := ic.do("GET", link, nil); !strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatal("a consumed invite must not redeem again")
	}
}

func TestOrgInvite_WrongAccountDoesNotBurnToken(t *testing.T) {
	a, s, mailer := newOrgAuth(t)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner})
	oc := newClient(t, a)
	oc.login("o@x.com", "hunter2hunter2")
	if w := oc.do("POST", "/auth/org/invites", map[string]any{"email": "right@x.com"}); w.Code != 200 {
		t.Fatalf("invite = %d", w.Code)
	}
	link := inviteLink(t, mailer, "invited you to join")

	// A DIFFERENT signed-in account clicking the link is refused — and must not consume the token.
	seedUser(t, s, "wrong@x.com", "hunter2hunter2", true)
	wc := newClient(t, a)
	wc.login("wrong@x.com", "hunter2hunter2")
	if w := wc.do("GET", link, nil); !strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatal("the wrong account must be refused")
	}

	// The intended account still redeems fine afterwards.
	right := seedUser(t, s, "right@x.com", "hunter2hunter2", true)
	rc := newClient(t, a)
	rc.login("right@x.com", "hunter2hunter2")
	if w := rc.do("GET", link, nil); strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatalf("the invited account must still redeem: %q", w.Header().Get("Location"))
	}
	if role, err := s.OrgRole(o.ID, right.ID); err != nil || role != authx.OrgRoleMember {
		t.Fatalf("membership = %q, %v", role, err)
	}
}

func TestOrgInvite_RecordsListRevokeAndReplace(t *testing.T) {
	a, s, mailer := newOrgAuth(t)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{owner.ID: authx.OrgRoleOwner})
	oc := newClient(t, a)
	oc.login("o@x.com", "hunter2hunter2")

	// Nothing in the accept URL can be tampered with anymore (org+role bind to the record); a
	// corrupted token simply matches no invite.
	_ = oc.do("POST", "/auth/org/invites", map[string]any{"email": "new@x.com", "role": "member"})
	link := inviteLink(t, mailer, "invited you to join")
	invitee := seedUser(t, s, "new@x.com", "hunter2hunter2", true)
	ic := newClient(t, a)
	ic.login("new@x.com", "hunter2hunter2")
	if w := ic.do("GET", link+"x", nil); !strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatal("a corrupted token must be refused")
	}

	// Re-inviting the same address REPLACES the pending invite (role update, no row stacking) —
	// and invalidates the earlier link.
	if w := oc.do("POST", "/auth/org/invites", map[string]any{"email": "new@x.com", "role": "admin"}); w.Code != 200 {
		t.Fatalf("re-invite = %d", w.Code)
	}
	lst := decode(t, oc.do("GET", "/auth/org/invites", nil))
	invites, _ := lst["invites"].([]any)
	if len(invites) != 1 {
		t.Fatalf("re-invite must replace, not stack: %v", lst)
	}
	first := invites[0].(map[string]any)
	if first["role"] != "admin" || first["email"] != "new@x.com" || first["invitedBy"] != "o@x.com" {
		t.Fatalf("pending invite record = %v", first)
	}
	if w := ic.do("GET", link, nil); !strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatal("a replaced invite's old link must be dead")
	}

	// Revoke kills the pending invite before redemption.
	id := first["id"].(string)
	if w := oc.do("DELETE", "/auth/org/invites/"+id, nil); w.Code != 200 {
		t.Fatalf("revoke = %d: %s", w.Code, w.Body.String())
	}
	link2 := inviteLink(t, mailer, "invited you to join") // the re-invite email
	if w := ic.do("GET", link2, nil); !strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatal("a revoked invite must not redeem")
	}
	if _, err := s.OrgRole(o.ID, invitee.ID); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatalf("no membership may exist after revocation: %v", err)
	}
	lst = decode(t, oc.do("GET", "/auth/org/invites", nil))
	if invites, _ := lst["invites"].([]any); len(invites) != 0 {
		t.Fatalf("revoked invite must leave the pending list: %v", lst)
	}
}

func TestOrgInvite_RequiresManagerAndOwnerForOwner(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	admin := seedUser(t, s, "a@x.com", "hunter2hunter2", true)
	member := seedUser(t, s, "m@x.com", "hunter2hunter2", true)
	seedOrg(t, s, "acme", map[string]string{admin.ID: authx.OrgRoleAdmin, member.ID: authx.OrgRoleMember})

	mc := newClient(t, a)
	mc.login("m@x.com", "hunter2hunter2")
	if w := mc.do("POST", "/auth/org/invites", map[string]any{"email": "x@x.com"}); w.Code != http.StatusForbidden {
		t.Fatalf("a plain member must not invite: %d", w.Code)
	}
	ac := newClient(t, a)
	ac.login("a@x.com", "hunter2hunter2")
	if w := ac.do("POST", "/auth/org/invites", map[string]any{"email": "x@x.com", "role": "owner"}); w.Code != http.StatusForbidden {
		t.Fatalf("an admin must not invite an OWNER: %d", w.Code)
	}
}

// --- self-service member management ---

func TestOrgMembers_LastOwnerGuardAndLeave(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	owner := seedUser(t, s, "o@x.com", "hunter2hunter2", true)
	admin := seedUser(t, s, "a@x.com", "hunter2hunter2", true)
	member := seedUser(t, s, "m@x.com", "hunter2hunter2", true)
	o := seedOrg(t, s, "acme", map[string]string{
		owner.ID: authx.OrgRoleOwner, admin.ID: authx.OrgRoleAdmin, member.ID: authx.OrgRoleMember,
	})

	oc := newClient(t, a)
	oc.login("o@x.com", "hunter2hunter2")
	ac := newClient(t, a)
	ac.login("a@x.com", "hunter2hunter2")
	mc := newClient(t, a)
	mc.login("m@x.com", "hunter2hunter2")

	uidPath := func(id string) string { return "/auth/org/members/" + id }

	// Any member may list; the view carries no operator-only fields.
	lst := decode(t, mc.do("GET", "/auth/org/members", nil))
	if members, _ := lst["members"].([]any); len(members) != 3 {
		t.Fatalf("members = %v", lst)
	} else if m0 := members[0].(map[string]any); m0["Banned"] != nil || m0["Disabled"] != nil {
		t.Fatalf("member view must not leak operator fields: %v", m0)
	}

	// A plain member manages nothing.
	if w := mc.do("POST", uidPath(admin.ID), map[string]any{"role": "member"}); w.Code != http.StatusForbidden {
		t.Fatalf("member setting roles = %d", w.Code)
	}
	// An admin manages non-owners but can't touch the owner role.
	if w := ac.do("POST", uidPath(member.ID), map[string]any{"role": "billing"}); w.Code != 200 {
		t.Fatalf("admin set custom role = %d: %s", w.Code, w.Body.String())
	}
	if w := ac.do("POST", uidPath(owner.ID), map[string]any{"role": "member"}); w.Code != http.StatusForbidden {
		t.Fatalf("admin demoting an owner = %d, want 403", w.Code)
	}
	if w := ac.do("DELETE", uidPath(owner.ID), nil); w.Code != http.StatusForbidden {
		t.Fatalf("admin removing an owner = %d, want 403", w.Code)
	}

	// The last owner can't demote or remove themself...
	if w := oc.do("POST", uidPath(owner.ID), map[string]any{"role": "member"}); w.Code != http.StatusConflict {
		t.Fatalf("sole-owner demote = %d, want 409", w.Code)
	}
	if w := oc.do("DELETE", uidPath(owner.ID), nil); w.Code != http.StatusConflict {
		t.Fatalf("sole-owner leave = %d, want 409", w.Code)
	}
	// ...until another owner exists.
	if w := oc.do("POST", uidPath(admin.ID), map[string]any{"role": "owner"}); w.Code != 200 {
		t.Fatalf("promote second owner = %d", w.Code)
	}
	if w := oc.do("DELETE", uidPath(owner.ID), nil); w.Code != 200 {
		t.Fatalf("owner leave with a second owner = %d", w.Code)
	}
	if _, err := s.OrgRole(o.ID, owner.ID); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatalf("leaver must be removed: %v", err)
	}
	// Leaving cleared the leaver's active org in their re-minted cookie.
	me := decode(t, oc.do("GET", "/auth/me", nil))
	if me["org"] != nil {
		t.Fatalf("leaver's active org must be cleared: %v", me["org"])
	}
}

// --- admin verbs ---

func TestAdminOrgVerbs(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	seedUser(t, s, "owner@example.com", "hunter2hunter2", true) // Config.OwnerEmail → adminGuard
	u := seedUser(t, s, "u@x.com", "hunter2hunter2", true)

	c := newClient(t, a)
	c.login("owner@example.com", "hunter2hunter2")

	// Create (+ validation + conflict).
	w := c.do("POST", "/auth/admin/orgs", map[string]any{"slug": "acme", "name": "Acme"})
	if w.Code != 200 {
		t.Fatalf("create = %d: %s", w.Code, w.Body.String())
	}
	created := decode(t, w)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("created org has no id: %v", created)
	}
	if w := c.do("POST", "/auth/admin/orgs", map[string]any{"slug": "Bad Slug!", "name": "x"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad slug = %d", w.Code)
	}
	if w := c.do("POST", "/auth/admin/orgs", map[string]any{"slug": "acme", "name": "again"}); w.Code != http.StatusConflict {
		t.Fatalf("dup slug = %d", w.Code)
	}

	// Members. A typo'd user ID is a 404, not a silent dangling membership.
	if w := c.do("POST", "/auth/admin/orgs/"+id+"/members/9999", map[string]any{"role": "owner"}); w.Code != http.StatusNotFound {
		t.Fatalf("admin add missing user = %d, want 404", w.Code)
	}
	if w := c.do("POST", "/auth/admin/orgs/"+id+"/members/"+u.ID, map[string]any{"role": "owner"}); w.Code != 200 {
		t.Fatalf("admin add member = %d: %s", w.Code, w.Body.String())
	}
	lst := decode(t, c.do("GET", "/auth/admin/orgs/"+id+"/members", nil))
	if members, _ := lst["members"].([]any); len(members) != 1 {
		t.Fatalf("members = %v", lst)
	}
	// The ADMIN api skips the last-owner guard (operator recovery path).
	if w := c.do("DELETE", "/auth/admin/orgs/"+id+"/members/"+u.ID, nil); w.Code != 200 {
		t.Fatalf("admin remove sole owner = %d (admin must bypass the guard)", w.Code)
	}

	// Rename + delete + list.
	if w := c.do("POST", "/auth/admin/orgs/"+id, map[string]any{"name": "Acme Inc"}); w.Code != 200 {
		t.Fatalf("rename = %d", w.Code)
	}
	if w := c.do("DELETE", "/auth/admin/orgs/"+id, nil); w.Code != 200 {
		t.Fatalf("delete = %d", w.Code)
	}
	lst = decode(t, c.do("GET", "/auth/admin/orgs", nil))
	if orgs, _ := lst["orgs"].([]any); len(orgs) != 0 {
		t.Fatalf("orgs after delete = %v", lst)
	}

	// Unauthenticated callers are challenged.
	anon := newClient(t, a)
	if w := anon.do("GET", "/auth/admin/orgs", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("anon admin list = %d", w.Code)
	}
}
