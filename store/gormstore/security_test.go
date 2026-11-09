package gormstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	authx "github.com/alex-savin/go-auth-x"
)

// Regression tests for the 2026-11 security audit's store-level fixes.
func TestSecurityLinkingRules(t *testing.T) {
	t.Run("empty hash removes the password", func(t *testing.T) {
		s := newStore(t)
		u, _ := s.CreateLocalUser("a@x.com", "A")
		_ = s.SetPasswordHash(u.ID, "h", "bcrypt")
		if err := s.SetPasswordHash(u.ID, "", ""); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.PasswordHash(u.ID); !errors.Is(err, authx.ErrNoCredential) {
			t.Fatalf("want ErrNoCredential, got %v", err)
		}
	})
	t.Run("a changed email is only as verified as its assertion", func(t *testing.T) {
		s := newStore(t)
		u, _ := s.UpsertUserOnLogin("scim:x", "mine@evil.test", "X", true)
		got, err := s.UpsertUserOnLogin("scim:x", "victim@x.com", "X", false)
		if err != nil || got.ID != u.ID || got.EmailVerified {
			t.Fatalf("moved to an unproven address it must be unverified: %+v %v", got, err)
		}
		if got, _ := s.UpsertUserOnLogin("scim:x", "victim@x.com", "X", false); got.EmailVerified {
			t.Fatal("re-asserting it unproven must not verify it")
		}
	})
	t.Run("an empty email never links accounts", func(t *testing.T) {
		s := newStore(t)
		alice, err := s.UpsertUserOnLogin("idp|alice", "", "Alice", true)
		if err != nil {
			t.Fatal(err)
		}
		bob, err := s.UpsertUserOnLogin("idp|bob", "", "Bob", true)
		if err != nil || bob.ID == alice.ID {
			t.Fatalf("two email-less identities must get two accounts: %v %+v", err, bob)
		}
		_, _ = s.UpsertUserOnLogin("idp|carol", "carol@x.com", "Carol", true)
		if got, _ := s.UpsertUserOnLogin("idp|carol", "", "Carol", true); got.Email != "carol@x.com" {
			t.Fatalf("an identity asserting no email must leave the stored one: %q", got.Email)
		}
	})
	t.Run("claiming a bootstrap row drops a planted password", func(t *testing.T) {
		s := newStore(t)
		b, _ := s.UpsertUserOnLogin("bootstrap:owner@x.com", "owner@x.com", "Owner", false)
		_ = s.SetPasswordHash(b.ID, "planted", "bcrypt")
		got, err := s.UpsertUserOnLogin("idp|owner", "owner@x.com", "Owner", true)
		if err != nil || got.ID != b.ID {
			t.Fatalf("the owner's first login must claim the placeholder: %+v %v", got, err)
		}
		if _, _, err := s.PasswordHash(b.ID); !errors.Is(err, authx.ErrNoCredential) {
			t.Fatal("a password on the placeholder must not pass to its claimant")
		}
	})
}

// A login writes only the columns it sets, and only to the row it read: a ban or a deletion that lands
// between the login's read and its write survives it (the write used to put the whole stale row back,
// re-inserting a deleted one).
func TestLoginDoesntWriteBackStaleUser(t *testing.T) {
	for _, tc := range []struct {
		name       string
		concurrent func(s *Store, id string)
		check      func(t *testing.T, s *Store, id string, loginErr error)
	}{
		{"ban", func(s *Store, id string) { _ = s.SetUserBan(id, true, nil, "fraud"); _ = s.SetUserDisabled(id, true) },
			func(t *testing.T, s *Store, id string, _ error) {
				if u, _ := s.UserByID(id); !u.Banned || !u.Disabled {
					t.Fatalf("the concurrent ban was undone: %+v", u)
				}
			}},
		{"delete", func(s *Store, id string) { _ = s.DeleteUser(id) },
			func(t *testing.T, s *Store, id string, loginErr error) {
				if _, err := s.UserByID(id); err == nil {
					t.Fatal("the deleted user was re-inserted")
				}
				if loginErr == nil {
					t.Fatal("the login on a deleted row must fail")
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			u, err := s.UpsertUserOnLogin("idp|u", "u@x.com", "U", true)
			if err != nil {
				t.Fatal(err)
			}
			fired := false
			if err := s.db.Callback().Update().Before("gorm:update").Register("test:concurrent", func(db *gorm.DB) {
				if fired || db.Statement.Table != "authx_users" {
					return
				}
				fired = true
				tc.concurrent(s, u.ID)
			}); err != nil {
				t.Fatal(err)
			}
			_, loginErr := s.UpsertUserOnLogin("idp|u", "u@x.com", "U", true)
			if !fired {
				t.Fatal("the concurrent change never ran")
			}
			tc.check(t, s, u.ID, loginErr)
		})
	}
}

// A local login's identity carries the stored email as read; the Authorizer doesn't write it back, so
// an email change made meanwhile stands.
func TestLocalLoginDoesntRevertEmailChange(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("old@x.com", "U")
	_ = s.SetEmailVerified(u.ID, true)
	if err := s.SetEmail(u.ID, "new@x.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorizer().Authorize(context.Background(), authx.Identity{Subject: u.Sub, Email: "old@x.com", EmailVerified: true, Local: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByID(u.ID); got.Email != "new@x.com" {
		t.Fatalf("the email change was reverted to %q", got.Email)
	}
}

// Disabling or banning a user ends their recorded sessions, and an account rebound to a new subject
// takes its sessions along (so revoking by its subject still finds them).
func TestSessionsFollowTheAccount(t *testing.T) {
	s := newStore(t)
	u, _ := s.UpsertExternalUser("ldap:bob", "bob@corp.com", "Bob", true)
	rec := func(sid, sub string) {
		_ = s.RecordSession(authx.SessionRecord{SID: sid, Subject: sub, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	}
	rec("s-ldap", "ldap:bob")
	if _, err := s.Authorizer().Authorize(context.Background(), authx.Identity{Subject: "kc|bob", Email: "bob@corp.com", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListSessionsForUser("kc|bob"); len(got) != 1 {
		t.Fatalf("the rebound account's session must move to its new subject: %v", got)
	}
	rec("s-kc", "kc|bob")
	if err := s.SetUserDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"s-ldap", "s-kc"} {
		if revoked, _ := s.IsRevoked(sid); !revoked {
			t.Fatalf("session %s must end when the user is disabled", sid)
		}
	}
	_ = s.SetUserDisabled(u.ID, false)
	rec("s-later", "kc|bob")
	_ = s.SetUserBan(u.ID, true, nil, "abuse")
	if revoked, _ := s.IsRevoked("s-later"); !revoked {
		t.Fatal("a ban must end the user's sessions")
	}
}

// A provider is listed once however many identities a user has with it: the last-sign-in-method guard
// counts providers, and an unlink removes all of a provider's identities at once.
func TestOAuthIdentitiesListsProvidersOnce(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("ms@x.com", "")
	_ = s.LinkOAuth(u.ID, "microsoft", "personal", "ms@x.com")
	_ = s.LinkOAuth(u.ID, "microsoft", "work", "ms@x.com")
	if got, _ := s.OAuthIdentities(u.ID); len(got) != 1 || got[0] != "microsoft" {
		t.Fatalf("OAuthIdentities = %v, want [microsoft]", got)
	}
}
