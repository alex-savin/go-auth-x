package memory

import (
	"context"
	"errors"
	"testing"
	"time"

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

// A local login's identity carries the stored email as read; the Authorizer doesn't write it back, so
// an email change made meanwhile stands.
func TestLocalLoginDoesntRevertEmailChange(t *testing.T) {
	s := New()
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
	s := New()
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

// A provisioning source that moves an existing account to another address hands the account to
// whoever holds that mailbox: nothing that signs in comes along, and what was signed in ends. A login
// that reports a new address for its own account (UpsertUserOnLogin) changes none of that.
func TestProvisionedEmailMoveResetsSignIn(t *testing.T) {
	s := New()
	seed := func(sub, email string) *authx.AuthUser {
		t.Helper()
		u, err := s.UpsertExternalUser(sub, email, "U", true)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.SetPasswordHash(u.ID, "h", "bcrypt")
		_ = s.AddPasskey(u.ID, authx.Passkey{CredentialID: []byte("cred-" + sub), Name: "key"})
		_ = s.LinkOAuth(u.ID, "google", "g-"+sub, email)
		_ = s.SetTOTPSecret(u.ID, "SECRET")
		_ = s.EnableTOTP(u.ID)
		_ = s.CreateToken("reset", u.ID, email, []byte("tok-"+sub), time.Now().Add(time.Hour))
		_ = s.RecordSession(authx.SessionRecord{SID: "sid-" + sub, Subject: sub, UserID: u.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
		if err := s.CreateOAuthGrant(&authx.OAuthGrant{ID: "grant-" + sub, ClientID: "c", Subject: sub, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		return u
	}
	signIns := func(u *authx.AuthUser, sub string) (n int) {
		t.Helper()
		if _, _, err := s.PasswordHash(u.ID); err == nil {
			n++
		}
		if pks, _ := s.Passkeys(u.ID); len(pks) != 0 {
			n++
		}
		if _, err := s.UserByOAuth("google", "g-"+sub); err == nil {
			n++
		}
		if _, err := s.TOTP(u.ID); err == nil {
			n++
		}
		if _, err := s.PeekToken("reset", []byte("tok-"+sub)); err == nil {
			n++
		}
		if revoked, _ := s.IsRevoked("sid-" + sub); !revoked {
			n++
		}
		if _, err := s.OAuthGrant("grant-" + sub); err == nil {
			n++
		}
		return n
	}
	g, _ := s.CreateGroup("staff", "")

	u := seed("scim:mallory", "mallory@evil.test")
	if err := s.AddUserToGroup(u.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	if n := signIns(u, "scim:mallory"); n != 7 {
		t.Fatalf("precondition: %d of 7 sign-in records", n)
	}
	if _, err := s.UpsertExternalUser("scim:mallory", "mallory@evil.test", "Renamed", true); err != nil {
		t.Fatal(err)
	}
	if n := signIns(u, "scim:mallory"); n != 7 {
		t.Fatalf("an update that keeps the address must keep the account's sign-in: %d of 7 left", n)
	}
	moved, err := s.UpsertExternalUser("scim:mallory", "owner@example.com", "U", true)
	if err != nil {
		t.Fatal(err)
	}
	if moved.ID != u.ID || moved.Email != "owner@example.com" {
		t.Fatalf("the move must keep the account: %+v", moved)
	}
	if n := signIns(u, "scim:mallory"); n != 0 {
		t.Fatalf("%d sign-in records survived the move", n)
	}
	if gs, _ := s.UserGroups(u.ID); len(gs) != 1 {
		t.Fatalf("the account's memberships must stay: %+v", gs)
	}

	login := seed("oidc-sub-1", "old@corp.com")
	if _, err := s.UpsertUserOnLogin("oidc-sub-1", "new@corp.com", "U", true); err != nil {
		t.Fatal(err)
	}
	if n := signIns(login, "oidc-sub-1"); n != 7 {
		t.Fatalf("a login reporting a new address must keep the account's sign-in: %d of 7 left", n)
	}
}

// A signup's password is written only while the account is unverified, and a mailbox proof verifies
// the account and drops any password but the one it is told to keep — each in one step, so a signup
// and a proof can't interleave into an unproven password on a verified account.
func TestSignupStoreWritesAreConditional(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@x.com", "A")
	if set, err := s.SetPasswordHashIfUnverified(u.ID, "h1", "bcrypt"); err != nil || !set {
		t.Fatalf("an unverified account takes a signup's password: %v, %v", set, err)
	}
	if err := s.VerifyEmailKeepingPassword(u.ID, "h1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByID(u.ID); !got.EmailVerified {
		t.Fatal("the account must be verified")
	}
	if h, _, err := s.PasswordHash(u.ID); err != nil || h != "h1" {
		t.Fatalf("the password it was told to keep must stay: %q, %v", h, err)
	}
	if set, err := s.SetPasswordHashIfUnverified(u.ID, "h2", "bcrypt"); err != nil || set {
		t.Fatalf("a verified account must refuse a signup's password: %v, %v", set, err)
	}
	if h, _, _ := s.PasswordHash(u.ID); h != "h1" {
		t.Fatalf("the refused write changed the password to %q", h)
	}

	for _, keep := range []string{"", "another-hash"} {
		v, _ := s.CreateLocalUser("keep"+keep+"@x.com", "B")
		_, _ = s.SetPasswordHashIfUnverified(v.ID, "squatter", "bcrypt")
		if err := s.VerifyEmailKeepingPassword(v.ID, keep); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.PasswordHash(v.ID); !errors.Is(err, authx.ErrNoCredential) {
			t.Fatalf("keeping %q must drop a different password, got %v", keep, err)
		}
	}
	if set, err := s.SetPasswordHashIfUnverified("999999", "h", "bcrypt"); err != nil || set {
		t.Fatalf("a missing account takes no password: %v, %v", set, err)
	}
	if _, _, err := s.PasswordHash("999999"); !errors.Is(err, authx.ErrNoCredential) {
		t.Fatal("no password row may be left for a user that doesn't exist")
	}
}

// Reclaiming an unverified account for a verified login ends that account's sessions and removes its
// OAuth records, as deleting it does: it can have both, signed in before a provisioning source moved
// it onto the address.
func TestReclaimEndsTheOldAccountsSessionsAndGrants(t *testing.T) {
	s := New()
	old, _ := s.UpsertUserOnLogin("scim:old", "taken@x.com", "Old", false) // unverified, not a bootstrap row
	_ = s.RecordSession(authx.SessionRecord{SID: "sid-old", Subject: "scim:old", UserID: old.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err := s.CreateOAuthGrant(&authx.OAuthGrant{ID: "grant-old", ClientID: "c", Subject: "scim:old", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	nu, err := s.UpsertUserOnLogin("oidc:new", "taken@x.com", "New", true)
	if err != nil || nu.ID == old.ID {
		t.Fatalf("a verified login reclaims the address with a new account: %+v, %v", nu, err)
	}
	if revoked, _ := s.IsRevoked("sid-old"); !revoked {
		t.Fatal("the reclaimed account's session is still live")
	}
	if _, err := s.OAuthGrant("grant-old"); err == nil {
		t.Fatal("the reclaimed account's OAuth grant was left behind")
	}
}
