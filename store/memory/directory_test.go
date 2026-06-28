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
