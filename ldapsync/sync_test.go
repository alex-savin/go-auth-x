package ldapsync

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// fakeLDAP serves fixed users and groups, by base DN.
type fakeLDAP struct {
	users, groups []*ldap.Entry
	userErr       error
	closed        bool
}

func (f *fakeLDAP) SearchWithPaging(req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	switch req.BaseDN {
	case "ou=people,dc=x":
		if f.userErr != nil {
			return nil, f.userErr
		}
		return &ldap.SearchResult{Entries: f.users}, nil
	case "ou=groups,dc=x":
		return &ldap.SearchResult{Entries: f.groups}, nil
	}
	return nil, errors.New("unexpected base DN " + req.BaseDN)
}

func (f *fakeLDAP) Close() error { f.closed = true; return nil }

func person(uid, mail string) *ldap.Entry {
	attrs := map[string][]string{"cn": {strings.ToUpper(uid)}}
	if uid != "" {
		attrs["uid"] = []string{uid}
	}
	if mail != "" {
		attrs["mail"] = []string{mail}
	}
	return ldap.NewEntry("uid="+uid+",ou=people,dc=x", attrs)
}

func syncer(dir authx.DirectoryStore, f *fakeLDAP, deprovision bool) *Syncer {
	s := New(Config{URL: "ldaps://ldap.x", UserBaseDN: "ou=people,dc=x", GroupBaseDN: "ou=groups,dc=x", DeprovisionMissing: deprovision}, dir)
	s.connect = func() (searcher, error) { return f, nil }
	return s
}

func memberIDs(t *testing.T, s *memory.Store, group string) []string {
	t.Helper()
	g, err := s.GroupByName(group)
	if err != nil {
		t.Fatal(err)
	}
	us, _ := s.GroupMembers(g.ID)
	var subs []string
	for _, u := range us {
		subs = append(subs, u.Sub)
	}
	slices.Sort(subs)
	return subs
}

func TestSync_UsersGroupsAndMembership(t *testing.T) {
	store := memory.New()
	f := &fakeLDAP{
		users: []*ldap.Entry{person("alice", "alice@x.com"), person("bob", "bob@x.com"), person("", "nouid@x.com"), person("nomail", "")},
		groups: []*ldap.Entry{
			ldap.NewEntry("cn=eng,ou=groups,dc=x", map[string][]string{"cn": {"eng"}, "member": {
				"UID=Alice, OU=People, DC=x", // the entry's DN, written differently
				"bob",                        // a bare uid (posixGroup style)
				"uid=ghost,ou=people,dc=x",   // not a synced user
			}}),
			ldap.NewEntry("cn=nameless,ou=groups,dc=x", map[string][]string{"member": {"bob"}}),
		},
	}
	for run := range 2 { // a second run changes nothing
		res, err := syncer(store, f, false).Sync()
		if err != nil {
			t.Fatal(err)
		}
		if res.Users != 2 || res.Groups != 1 || res.Memberships != 2 || len(res.Errors) != 0 {
			t.Fatalf("run %d: result = %+v", run, res)
		}
	}
	if !f.closed {
		t.Fatal("the connection must be closed")
	}
	users, _ := store.ListUsers()
	if len(users) != 2 {
		t.Fatalf("want exactly the 2 complete LDAP users, got %d", len(users))
	}
	if got := memberIDs(t, store, "eng"); !slices.Equal(got, []string{"ldap:alice", "ldap:bob"}) {
		t.Fatalf("eng members = %v", got)
	}
}

func TestSync_DeprovisionMissing(t *testing.T) {
	store := memory.New()
	_, _ = store.UpsertExternalUser("ldap:carol", "carol@x.com", "Carol", true) // synced before, gone from LDAP
	local, _ := store.CreateLocalUser("dave@x.com", "Dave")                     // not from LDAP
	f := &fakeLDAP{users: []*ldap.Entry{person("alice", "alice@x.com")}}

	res, err := syncer(store, f, true).Sync()
	if err != nil {
		t.Fatal(err)
	}
	if res.Deprovisioned != 1 {
		t.Fatalf("want 1 deprovisioned, got %+v", res)
	}
	carol, _ := store.UserBySub("ldap:carol")
	dave, _ := store.UserByID(local.ID)
	alice, _ := store.UserBySub("ldap:alice")
	if !carol.Disabled || dave.Disabled || alice.Disabled {
		t.Fatalf("only the vanished LDAP user may be disabled: carol=%v dave=%v alice=%v", carol.Disabled, dave.Disabled, alice.Disabled)
	}
	if res, _ := syncer(store, f, true).Sync(); res.Deprovisioned != 0 {
		t.Fatalf("an already-disabled user must not be counted again: %+v", res)
	}
}

// An empty user search (a wrong base DN, a replication blip) must never disable everyone.
func TestSync_DeprovisionSafetyGuard(t *testing.T) {
	store := memory.New()
	_, _ = store.UpsertExternalUser("ldap:carol", "carol@x.com", "Carol", true)
	res, err := syncer(store, &fakeLDAP{}, true).Sync()
	if err != nil {
		t.Fatal(err)
	}
	if carol, _ := store.UserBySub("ldap:carol"); carol.Disabled || res.Deprovisioned != 0 {
		t.Fatal("an empty LDAP result must not deprovision anyone")
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "deprovision skipped") {
		t.Fatalf("the skip must be reported: %v", res.Errors)
	}
}

// failUpsert fails UpsertExternalUser for one subject.
type failUpsert struct {
	*memory.Store
	sub string
}

func (f failUpsert) UpsertExternalUser(sub, email, name string, verified bool) (*authx.AuthUser, error) {
	if sub == f.sub {
		return nil, errors.New("database busy")
	}
	return f.Store.UpsertExternalUser(sub, email, name, verified)
}

// A user present in LDAP whose upsert fails this run is still present: never deprovisioned.
func TestSync_FailedUpsertIsNotDeprovisioned(t *testing.T) {
	store := memory.New()
	_, _ = store.UpsertExternalUser("ldap:alice", "alice@x.com", "Alice", true)
	f := &fakeLDAP{users: []*ldap.Entry{person("alice", "alice@x.com"), person("bob", "bob@x.com")}}
	res, err := syncer(failUpsert{store, "ldap:alice"}, f, true).Sync()
	if err != nil {
		t.Fatal(err)
	}
	if alice, _ := store.UserBySub("ldap:alice"); alice.Disabled {
		t.Fatal("a present user must not be deprovisioned because their upsert failed")
	}
	if res.Users != 1 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "alice") {
		t.Fatalf("result = %+v", res)
	}
}

func TestSync_Errors(t *testing.T) {
	if _, err := syncer(memory.New(), &fakeLDAP{userErr: errors.New("size limit")}, false).Sync(); err == nil || !strings.Contains(err.Error(), "user search") {
		t.Fatalf("a failed user search must fail the sync, got %v", err)
	}
	s := syncer(memory.New(), nil, false)
	s.connect = func() (searcher, error) { return nil, errors.New("connection refused") }
	if _, err := s.Sync(); err == nil {
		t.Fatal("a failed connection must fail the sync")
	}
}
