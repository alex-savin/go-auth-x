package memory

import (
	"testing"

	authx "github.com/alex-savin/go-auth-x"
)

func TestDirectory(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@b.com", "A")

	g, err := s.CreateGroup("admins", "instance admins")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := s.AddUserToGroup(u.ID, g.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if gs, _ := s.UserGroups(u.ID); len(gs) != 1 || gs[0].Name != "admins" {
		t.Fatalf("user groups: %+v", gs)
	}
	if m, _ := s.GroupMembers(g.ID); len(m) != 1 || m[0].ID != u.ID {
		t.Fatalf("group members: %+v", m)
	}

	info, err := s.CreateAPIKey("ci", []string{"admins"}, []string{"scim"}, "axk_abc123", []byte("hash-bytes"), nil)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	got, err := s.APIKeyByHash([]byte("hash-bytes"))
	if err != nil || got.ID != info.ID || len(got.Groups) != 1 || got.Groups[0] != "admins" {
		t.Fatalf("apikey by hash: err=%v key=%+v", err, got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "scim" {
		t.Fatalf("apikey scopes round-trip: %+v", got.Scopes)
	}
	if !authx.KeyHasScope(got, "scim") || authx.KeyHasScope(got, "admin") {
		t.Fatalf("scope check wrong for %+v", got.Scopes)
	}
	if _, err := s.APIKeyByHash([]byte("nope")); err != authx.ErrNoCredential {
		t.Fatalf("unknown key: want ErrNoCredential, got %v", err)
	}

	if err := s.RemoveUserFromGroup(u.ID, g.ID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if gs, _ := s.UserGroups(u.ID); len(gs) != 0 {
		t.Fatalf("after removal: %+v", gs)
	}
}

func TestBatchGroupMembership(t *testing.T) {
	s := New()
	u1, _ := s.CreateLocalUser("u1@x.com", "U1")
	u2, _ := s.CreateLocalUser("u2@x.com", "U2")
	u3, _ := s.CreateLocalUser("u3@x.com", "U3")
	g, _ := s.CreateGroup("eng", "")

	// Unparseable ids are skipped, never a failed batch; re-adding is idempotent.
	for range 2 {
		if err := s.AddUsersToGroup([]string{u1.ID, "bogus", u2.ID, u3.ID}, g.ID); err != nil {
			t.Fatal(err)
		}
	}
	if m, _ := s.GroupMembers(g.ID); len(m) != 3 {
		t.Fatalf("want 3 members, got %+v", m)
	}
	if err := s.RemoveUsersFromGroup([]string{u1.ID, "bogus", u3.ID}, g.ID); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.GroupMembers(g.ID); len(m) != 1 || m[0].ID != u2.ID {
		t.Fatalf("want only u2 left, got %+v", m)
	}
}
