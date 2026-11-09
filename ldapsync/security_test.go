package ldapsync

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/alex-savin/go-auth-x/store/memory"
)

// Regression test for the 2026-11 security audit (H2): an LDAP entry whose mail belongs to an account
// it didn't create is skipped — not rebound, not deleted — unless the operator opts in.
func TestSyncLeavesOtherAccountsAlone(t *testing.T) {
	store := memory.New()
	owner, _ := store.CreateLocalUser("owner@example.com", "Owner")
	_ = store.SetEmailVerified(owner.ID, true)
	pending, _ := store.CreateLocalUser("newhire@example.com", "New Hire") // unverified signup
	f := &fakeLDAP{users: []*ldap.Entry{person("alice", "alice@x.com"), person("mallory", "owner@example.com"), person("x", "newhire@example.com")}}

	res, err := syncer(store, f, true).Sync()
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := store.UserByID(owner.ID); u.Sub != owner.Sub {
		t.Fatalf("a verified local account must not be rebound: %q", u.Sub)
	}
	if _, err := store.UserByID(pending.ID); err != nil {
		t.Fatal("an unverified local account must not be deleted")
	}
	if res.Users != 1 || len(res.Errors) != 2 {
		t.Fatalf("both collisions must be skipped and reported: %+v", res)
	}

	s := syncer(store, f, true)
	s.cfg.AdoptExisting = true
	if _, err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if u, _ := store.UserByID(owner.ID); u.Sub != "ldap:mallory" {
		t.Fatalf("with AdoptExisting the entry takes the account: %q", u.Sub)
	}
}
