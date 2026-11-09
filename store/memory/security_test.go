package memory

import (
	"errors"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
)

// Regression tests for the 2026-11 security audit's store-level fixes.
func TestSecurityLinkingRules(t *testing.T) {
	t.Run("empty hash removes the password", func(t *testing.T) {
		s := New()
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
		s := New()
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
		s := New()
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
		s := New()
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
