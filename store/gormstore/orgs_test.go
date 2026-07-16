package gormstore

import (
	"errors"
	"testing"

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
