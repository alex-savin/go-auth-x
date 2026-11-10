package ldapsync

import (
	"strings"
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

func group(cn string, members ...string) *ldap.Entry {
	return ldap.NewEntry("cn="+cn+",ou=groups,dc=x", map[string][]string{"cn": {cn}, "member": members})
}

// A membership LDAP no longer lists is removed on the next sync: removed from the LDAP group, or the
// group gone from LDAP, a synced user loses what the group gates. Members that aren't LDAP users stay,
// and an empty search strips nothing.
func TestSyncRemovesMembershipsLDAPNoLongerLists(t *testing.T) {
	store := memory.New()
	local, _ := store.CreateLocalUser("operator@x.com", "Operator")
	f := &fakeLDAP{users: []*ldap.Entry{person("alice", "alice@x.com"), person("bob", "bob@x.com")},
		groups: []*ldap.Entry{group("admins", "uid=alice,ou=people,dc=x", "uid=bob,ou=people,dc=x"), group("staff", "uid=bob,ou=people,dc=x")}}
	if _, err := syncer(store, f, false).Sync(); err != nil {
		t.Fatal(err)
	}
	admins, _ := store.GroupByName("admins")
	_ = store.AddUserToGroup(local.ID, admins.ID) // an operator's own addition to the synced group

	// An empty group search (a mis-set base, a blip) removes nothing.
	saved := f.groups
	f.groups = nil
	if res, err := syncer(store, f, false).Sync(); err != nil || res.Removed != 0 || len(memberIDs(t, store, "admins")) != 3 {
		t.Fatalf("an empty group search must not strip memberships: %+v, %v", res, err)
	}
	f.groups = saved

	// Bob leaves admins in LDAP.
	f.groups = []*ldap.Entry{group("admins", "uid=alice,ou=people,dc=x"), group("staff", "uid=bob,ou=people,dc=x")}
	res, err := syncer(store, f, false).Sync()
	if err != nil || res.Removed != 1 {
		t.Fatalf("sync = %+v, %v; want one membership removed", res, err)
	}
	got := map[string]bool{}
	for _, sub := range memberIDs(t, store, "admins") {
		got[sub] = true
	}
	if got["ldap:bob"] || !got["ldap:alice"] || !got[local.Sub] {
		t.Fatalf("admins = %v: want alice and the operator's member, not bob", got)
	}

	// The staff group leaves LDAP: its LDAP members leave it.
	f.groups = []*ldap.Entry{group("admins", "uid=alice,ou=people,dc=x")}
	if _, err := syncer(store, f, false).Sync(); err != nil {
		t.Fatal(err)
	}
	if ids := memberIDs(t, store, "staff"); len(ids) != 0 {
		t.Fatalf("staff left LDAP but still has members %v", ids)
	}

	// KeepStaleMemberships restores the additive behaviour.
	keep := syncer(store, f, false)
	keep.cfg.KeepStaleMemberships = true
	f.groups = []*ldap.Entry{group("admins")}
	if res, err := keep.Sync(); err != nil || res.Removed != 0 || len(memberIDs(t, store, "admins")) != 2 {
		t.Fatalf("KeepStaleMemberships: %+v, %v, members %v", res, err, memberIDs(t, store, "admins"))
	}
}

// A uid on more than one entry is synced from none of them. The account "ldap:<uid>" would follow
// whichever entry came last — so an entry that can set its own uid attribute to an administrator's
// would move that account onto a mailbox of its choosing.
func TestSyncSkipsAUIDSharedByEntries(t *testing.T) {
	store := memory.New()
	f := &fakeLDAP{users: []*ldap.Entry{person("admin", "admin@x.com"), person("carol", "carol@x.com")}}
	if _, err := syncer(store, f, true).Sync(); err != nil {
		t.Fatal(err)
	}
	impostor := ldap.NewEntry("cn=mallory,ou=people,dc=x", map[string][]string{"uid": {"admin"}, "mail": {"mallory@evil.test"}, "cn": {"M"}})
	f.users = []*ldap.Entry{person("admin", "admin@x.com"), impostor, person("carol", "carol@x.com")}
	res, err := syncer(store, f, true).Sync()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := store.UserBySub("ldap:admin")
	if u.Email != "admin@x.com" || u.Disabled {
		t.Fatalf("the account was changed by an entry sharing its uid: %+v", u)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "share") || res.Users != 1 || res.Deprovisioned != 0 {
		t.Fatalf("the shared uid must be reported once, synced from no entry, and not deprovisioned: %+v", res)
	}
}

// With OwnGroupsOnly an LDAP group doesn't put its members into a same-named group the sync didn't
// make; without it (the default) it adopts the group, as before.
func TestSyncOwnGroupsOnly(t *testing.T) {
	for _, own := range []bool{true, false} {
		store := memory.New()
		_, _ = store.CreateGroup("admins", "created in-app by the operator")
		f := &fakeLDAP{users: []*ldap.Entry{person("mallory", "mallory@x.com")},
			groups: []*ldap.Entry{group("admins", "uid=mallory,ou=people,dc=x"), group("staff", "uid=mallory,ou=people,dc=x")}}
		s := syncer(store, f, false)
		s.cfg.OwnGroupsOnly = own
		res, err := s.Sync()
		if err != nil {
			t.Fatal(err)
		}
		if n := len(memberIDs(t, store, "admins")); own && (n != 0 || len(res.Errors) != 1) {
			t.Fatalf("OwnGroupsOnly: the operator's group got %d members, errors %v", n, res.Errors)
		} else if !own && n != 1 {
			t.Fatalf("default: the same-named group has %d members, want 1", n)
		}
		if len(memberIDs(t, store, "staff")) != 1 {
			t.Fatal("the sync's own group must be synced either way")
		}
	}
}

// MaxDeprovision stops a run that would disable more users than a real run plausibly does: a search
// that came back partial would otherwise disable everyone it missed.
func TestSyncMaxDeprovision(t *testing.T) {
	store := memory.New()
	f := &fakeLDAP{users: []*ldap.Entry{person("a", "a@x.com"), person("b", "b@x.com"), person("c", "c@x.com"), person("d", "d@x.com")}}
	if _, err := syncer(store, f, true).Sync(); err != nil {
		t.Fatal(err)
	}
	f.users = f.users[:1] // three of four vanish from the search
	s := syncer(store, f, true)
	s.cfg.MaxDeprovision = 2
	res, err := s.Sync()
	if err != nil || res.Deprovisioned != 0 || len(res.Errors) != 1 {
		t.Fatalf("over the cap: %+v, %v", res, err)
	}
	s.cfg.MaxDeprovision = 3
	if res, err := s.Sync(); err != nil || res.Deprovisioned != 3 {
		t.Fatalf("within the cap: %+v, %v", res, err)
	}
}

// Two DNs are the same after normalizing only when they are the same DN. A value's own separators
// stay escaped: an entry named "cn=admin\,ou\=staff" must not resolve as the member "cn=admin,ou=staff".
func TestNormalizeDNKeepsDistinctDNsApart(t *testing.T) {
	plain := normalizeDN(`cn=admin,ou=staff,ou=people,dc=x`)
	for _, other := range []string{`cn=admin\,ou\=staff,ou=people,dc=x`, `cn=admin+ou=staff,ou=people,dc=x`} {
		if normalizeDN(other) == plain {
			t.Fatalf("%q normalizes like the plain DN", other)
		}
	}
	for _, same := range []string{`CN=Admin, OU=Staff, ou=people, DC=x`, `cn=admin,ou=staff,ou=people,dc=x`} {
		if normalizeDN(same) != plain {
			t.Fatalf("%q should normalize like the plain DN: %q", same, normalizeDN(same))
		}
	}
	if normalizeDN(`cn=a+ou=b,dc=x`) != normalizeDN(`ou=b+cn=a,dc=x`) {
		t.Fatal("the parts of a multi-valued RDN compare in any order")
	}
}
