package gormstore

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

// TestOrgs_Conformance mirrors the memory store's org conformance suite over sqlite, so both
// reference stores keep identical OrgStore semantics (sentinels, upsert, cascades, idempotency).
func TestOrgs_Conformance(t *testing.T) {
	s := newStore(t)
	var store authx.OrgStore = s

	o, err := store.CreateOrg("acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateOrg("acme", "Dup"); err == nil {
		t.Fatal("a duplicate slug must be refused (unique index)")
	}
	if got, err := store.OrgBySlug("acme"); err != nil || got.ID != o.ID {
		t.Fatalf("OrgBySlug = %v, %v", got, err)
	}
	if _, err := store.OrgByID("999"); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("missing org must be ErrNoOrg, got %v", err)
	}
	if _, err := store.OrgByID("not-a-number"); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("a malformed opaque ID must read as ErrNoOrg, got %v", err)
	}
	if err := store.RenameOrg("999", "x"); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("renaming a missing org must be ErrNoOrg, got %v", err)
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
	// Upsert updates the role in place (no duplicate row — the unique index would reject one),
	// and re-setting the SAME role is idempotent (select-then-write, immune to MySQL's
	// zero-affected-rows-on-same-value UPDATE semantics).
	if err := store.SetOrgMember(o.ID, u.ID, authx.OrgRoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOrgMember(o.ID, u.ID, authx.OrgRoleOwner); err != nil {
		t.Fatalf("same-role re-set must be idempotent, got %v", err)
	}
	if role, _ := store.OrgRole(o.ID, u.ID); role != authx.OrgRoleOwner {
		t.Fatalf("upsert must update the role, got %q", role)
	}
	// A membership for a nonexistent user is refused (no dangling rows for future IDs).
	if err := store.SetOrgMember(o.ID, 4242, authx.OrgRoleOwner); !errors.Is(err, authx.ErrNoUser) {
		t.Fatalf("membership for a missing user must be ErrNoUser, got %v", err)
	}
	// A same-name rename is not misread as ErrNoOrg (explicit existence probe, not RowsAffected).
	if err := store.RenameOrg(o.ID, "Acme Inc"); err != nil {
		t.Fatalf("same-name rename must succeed, got %v", err)
	}
	if _, err := store.OrgRole(o.ID, 4242); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatalf("non-member must be ErrNotOrgMember, got %v", err)
	}
	if _, err := store.OrgRole("999", u.ID); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("role in a missing org must be ErrNoOrg, got %v", err)
	}
	if ms, _ := store.UserOrgs(u.ID); len(ms) != 1 || ms[0].Org.ID != o.ID || ms[0].Role != authx.OrgRoleOwner {
		t.Fatalf("UserOrgs = %+v", ms)
	}
	if mem, _ := store.OrgMembers(o.ID); len(mem) != 1 || mem[0].User.ID != u.ID || mem[0].Role != authx.OrgRoleOwner {
		t.Fatalf("OrgMembers = %+v", mem)
	}
	if _, err := store.OrgMembers("999"); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("members of a missing org must be ErrNoOrg, got %v", err)
	}
	if err := store.RemoveOrgMember(o.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveOrgMember(o.ID, u.ID); err != nil {
		t.Fatalf("RemoveOrgMember must be idempotent, got %v", err)
	}

	// A hard user delete cascades org memberships.
	_ = store.SetOrgMember(o.ID, u.ID, authx.OrgRoleMember)
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OrgRole(o.ID, u.ID); !errors.Is(err, authx.ErrNotOrgMember) {
		t.Fatalf("DeleteUser must cascade org membership, got %v", err)
	}

	// DeleteOrg cascades memberships and is idempotent.
	u2, _ := s.CreateLocalUser("n@x.com", "N")
	_ = store.SetOrgMember(o.ID, u2.ID, authx.OrgRoleMember)
	if err := store.DeleteOrg(o.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteOrg(o.ID); err != nil {
		t.Fatalf("DeleteOrg must be idempotent, got %v", err)
	}
	if _, err := store.OrgByID(o.ID); !errors.Is(err, authx.ErrNoOrg) {
		t.Fatalf("deleted org must be gone, got %v", err)
	}
	if ms, _ := store.UserOrgs(u2.ID); len(ms) != 0 {
		t.Fatalf("DeleteOrg must cascade memberships: %+v", ms)
	}
}

// TestOrgs_V07Conformance mirrors the memory store's v0.7 suite over sqlite: invites, org groups,
// org-bound keys, and the cascades (RemoveOrgMember → group rows, DeleteOrg → everything).
func TestOrgs_V07Conformance(t *testing.T) {
	s := newStore(t)
	var store authx.OrgStore = s
	u, _ := s.CreateLocalUser("m@x.com", "M")
	o, _ := store.CreateOrg("acme", "Acme")

	// Invite lifecycle.
	h1 := sha256.Sum256([]byte("tok1"))
	if _, err := store.CreateOrgInvite(o.ID, "new@x.com", "member", "m@x.com", h1[:], time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
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

	// Replacement + pending list + revoke + expiry.
	h2 := sha256.Sum256([]byte("tok2"))
	h3 := sha256.Sum256([]byte("tok3"))
	_, _ = store.CreateOrgInvite(o.ID, "x@x.com", "member", "", h2[:], time.Now().Add(time.Hour))
	_, _ = store.CreateOrgInvite(o.ID, "x@x.com", "admin", "", h3[:], time.Now().Add(time.Hour))
	if _, err := store.PeekOrgInvite(h2[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("replaced invite must be dead, got %v", err)
	}
	pending, _ := store.OrgInvites(o.ID)
	if len(pending) != 1 || pending[0].Role != "admin" {
		t.Fatalf("pending = %+v", pending)
	}
	if err := store.RevokeOrgInvite(o.ID, pending[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeekOrgInvite(h3[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("revoked invite must be dead, got %v", err)
	}
	h4 := sha256.Sum256([]byte("tok4"))
	_, _ = store.CreateOrgInvite(o.ID, "late@x.com", "member", "", h4[:], time.Now().Add(-time.Minute))
	if _, err := store.PeekOrgInvite(h4[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("expired invite must be ErrTokenInvalid, got %v", err)
	}

	// Org groups: per-org namespace, global verbs blind to them, membership cascade on removal.
	if _, err := s.CreateOrgGroup(o.ID, "eng", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrgGroup(o.ID, "eng", ""); err == nil {
		t.Fatal("duplicate (org, name) must be refused")
	}
	if _, err := s.CreateGroup("eng", ""); err != nil {
		t.Fatalf("a GLOBAL 'eng' must coexist with the org one: %v", err)
	}
	o2, _ := store.CreateOrg("globex", "Globex")
	if _, err := s.CreateOrgGroup(o2.ID, "eng", ""); err != nil {
		t.Fatalf("two orgs must both own 'eng': %v", err)
	}
	og, _ := s.OrgGroupByName(o.ID, "eng")
	if owner, _ := s.OrgOfGroup(og.ID); owner != o.ID {
		t.Fatalf("OrgOfGroup = %q, want %q", owner, o.ID)
	}
	gg, _ := s.GroupByName("eng")
	if owner, _ := s.OrgOfGroup(gg.ID); owner != "" {
		t.Fatalf("a global group's OrgOfGroup must be empty, got %q", owner)
	}
	if gs, _ := s.Groups(); len(gs) != 1 || gs[0].OrgID != "" {
		t.Fatalf("global Groups() must list only the global group: %+v", gs)
	}
	_ = store.SetOrgMember(o.ID, u.ID, authx.OrgRoleMember)
	_ = s.AddUserToGroup(u.ID, og.ID)
	if gs, _ := s.UserOrgGroups(o.ID, u.ID); len(gs) != 1 {
		t.Fatalf("UserOrgGroups = %+v", gs)
	}
	if err := store.RemoveOrgMember(o.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if gs, _ := s.UserOrgGroups(o.ID, u.ID); len(gs) != 0 {
		t.Fatalf("org-group membership must die with org membership: %+v", gs)
	}

	// Org-bound keys carry OrgID through the hash lookup; DeleteOrg cascades everything.
	kh := sha256.Sum256([]byte("axk_orgkey"))
	if _, err := s.CreateOrgAPIKey(o.ID, "k", nil, []string{"scim"}, "axk_orgk", kh[:], nil); err != nil {
		t.Fatal(err)
	}
	if info, err := s.APIKeyByHash(kh[:]); err != nil || info.OrgID != o.ID {
		t.Fatalf("org key lookup = %+v, %v", info, err)
	}
	if keys, _ := s.ListOrgAPIKeys(o.ID); len(keys) != 1 {
		t.Fatalf("ListOrgAPIKeys = %+v", keys)
	}
	h5 := sha256.Sum256([]byte("tok5"))
	_, _ = store.CreateOrgInvite(o.ID, "y@x.com", "member", "", h5[:], time.Now().Add(time.Hour))
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
	if gg2, err := s.GroupByName("eng"); err != nil || gg2.ID != gg.ID {
		t.Fatalf("the GLOBAL group must survive DeleteOrg: %v", err)
	}

	// DeleteUser erases pending invites addressed to the user's email (GDPR parity).
	victim, _ := s.CreateLocalUser("bye@x.com", "Bye")
	h6 := sha256.Sum256([]byte("tok6"))
	_, _ = store.CreateOrgInvite(o2.ID, "bye@x.com", "member", "", h6[:], time.Now().Add(time.Hour))
	if err := s.DeleteUser(victim.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeekOrgInvite(h6[:]); !errors.Is(err, authx.ErrTokenInvalid) {
		t.Fatalf("invites to an erased user must be gone, got %v", err)
	}
}
