package gormstore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	authx "github.com/alex-savin/go-auth-x"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "authx.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNew_UniqueEmailIndex(t *testing.T) {
	s := newStore(t)
	if _, err := s.CreateLocalUser("a@x.com", "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLocalUser("A@X.com", "dup"); err != authx.ErrEmailConflict {
		t.Fatalf("a duplicate email must return the typed ErrEmailConflict (parity with memory), got %v", err)
	}
}

func TestPeekTokenDoesNotConsume(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("a@x.com", "A")
	_ = s.CreateToken("password_reset", u.ID, "a@x.com", []byte("h"), time.Now().Add(time.Minute))
	// Peek is repeatable and non-destructive.
	if c, err := s.PeekToken("password_reset", []byte("h")); err != nil || c.UserID != u.ID {
		t.Fatalf("peek must return the claim without consuming: %v", err)
	}
	if _, err := s.PeekToken("password_reset", []byte("h")); err != nil {
		t.Fatal("a second peek must still succeed (token not consumed)")
	}
	// Consume then peek → invalid.
	if _, err := s.ConsumeToken("password_reset", []byte("h")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekToken("password_reset", []byte("h")); err != authx.ErrTokenInvalid {
		t.Fatal("peek after consume must be ErrTokenInvalid")
	}
}

func TestCredentialRoundTrip(t *testing.T) {
	s := newStore(t)
	u, err := s.CreateLocalUser("a@x.com", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByEmail("A@x.com"); got == nil || got.Sub != u.Sub {
		t.Fatal("UserByEmail must be case-insensitive")
	}
	if got, _ := s.UserBySub(u.Sub); got == nil || got.Email != "a@x.com" {
		t.Fatal("UserBySub round-trip failed")
	}
	if _, _, err := s.PasswordHash(u.ID); err != authx.ErrNoCredential {
		t.Fatalf("no password yet must be ErrNoCredential, got %v", err)
	}
	if err := s.SetPasswordHash(u.ID, "hash1", "bcrypt"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordHash(u.ID, "hash2", "bcrypt"); err != nil { // upsert on conflict
		t.Fatal(err)
	}
	if h, algo, _ := s.PasswordHash(u.ID); h != "hash2" || algo != "bcrypt" {
		t.Fatalf("password upsert failed: %q %q", h, algo)
	}
	if err := s.SetEmailVerified(u.ID, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserBySub(u.Sub); !got.EmailVerified {
		t.Fatal("SetEmailVerified not reflected")
	}
	// SetEmail: conflict against another user, then a clean change.
	other, _ := s.CreateLocalUser("taken@x.com", "O")
	_ = other
	if err := s.SetEmail(u.ID, "taken@x.com"); err != authx.ErrEmailConflict {
		t.Fatalf("SetEmail to a taken address must conflict, got %v", err)
	}
	if err := s.SetEmail(u.ID, "moved@x.com"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserBySub(u.Sub); got.Email != "moved@x.com" || !got.EmailVerified {
		t.Fatalf("SetEmail must update + verify: %+v", got)
	}
}

func TestPasskeys(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("a@x.com", "A")
	if err := s.AddPasskey(u.ID, authx.Passkey{CredentialID: []byte("cred1"), Name: "laptop", SignCount: 5}); err != nil {
		t.Fatal(err)
	}
	pks, _ := s.Passkeys(u.ID)
	if len(pks) != 1 || pks[0].Name != "laptop" {
		t.Fatalf("passkey list wrong: %+v", pks)
	}
	// Monotonic sign count: a lower value must not regress it.
	_ = s.TouchPasskey([]byte("cred1"), 3)
	pks, _ = s.Passkeys(u.ID)
	if pks[0].SignCount != 5 {
		t.Fatalf("sign count regressed to %d", pks[0].SignCount)
	}
	_ = s.TouchPasskey([]byte("cred1"), 9)
	pks, _ = s.Passkeys(u.ID)
	if pks[0].SignCount != 9 {
		t.Fatalf("sign count did not advance, got %d", pks[0].SignCount)
	}
	// Rename (and reject a wrong-user rename).
	_ = s.RenamePasskey(u.ID, pks[0].ID, "desktop")
	_ = s.RenamePasskey(u.ID+999, pks[0].ID, "hijack")
	pks, _ = s.Passkeys(u.ID)
	if pks[0].Name != "desktop" {
		t.Fatalf("rename wrong: %q", pks[0].Name)
	}
	// Remove (wrong user is a no-op, right user deletes).
	_ = s.RemovePasskey(u.ID+999, pks[0].ID)
	if pks2, _ := s.Passkeys(u.ID); len(pks2) != 1 {
		t.Fatal("wrong-user remove must be a no-op")
	}
	_ = s.RemovePasskey(u.ID, pks[0].ID)
	if pks2, _ := s.Passkeys(u.ID); len(pks2) != 0 {
		t.Fatal("passkey not removed")
	}
}

func TestOAuthLinkUnlink(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("a@x.com", "A")
	if err := s.LinkOAuth(u.ID, "google", "g1", "a@x.com"); err != nil {
		t.Fatal(err)
	}
	_ = s.LinkOAuth(u.ID, "google", "g1", "a@x.com") // idempotent (OnConflict DoNothing)
	_ = s.LinkOAuth(u.ID, "github", "h1", "a@x.com")
	if got, _ := s.UserByOAuth("google", "g1"); got == nil || got.ID != u.ID {
		t.Fatal("UserByOAuth failed")
	}
	ids, _ := s.OAuthIdentities(u.ID)
	if len(ids) != 2 || ids[0] != "github" || ids[1] != "google" {
		t.Fatalf("OAuthIdentities must be sorted [github google], got %v", ids)
	}
	_ = s.UnlinkOAuth(u.ID, "google")
	if ids, _ := s.OAuthIdentities(u.ID); len(ids) != 1 || ids[0] != "github" {
		t.Fatalf("after unlink want [github], got %v", ids)
	}
	if _, err := s.UserByOAuth("google", "g1"); err != authx.ErrNoUser {
		t.Fatal("unlinked identity must be gone")
	}
}

func TestTokens_SingleUseAndExpiry(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("a@x.com", "A")
	_ = s.CreateToken("magic_login", u.ID, "a@x.com", []byte("h1"), time.Now().Add(time.Minute))
	if _, err := s.ConsumeToken("verify_email", []byte("h1")); err != authx.ErrTokenInvalid {
		t.Fatal("a token must not redeem under the wrong purpose")
	}
	if c, err := s.ConsumeToken("magic_login", []byte("h1")); err != nil || c.UserID != u.ID {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := s.ConsumeToken("magic_login", []byte("h1")); err != authx.ErrTokenInvalid {
		t.Fatal("a token must be single-use")
	}
	// Expired token.
	_ = s.CreateToken("magic_login", u.ID, "a@x.com", []byte("h2"), time.Now().Add(-time.Second))
	if _, err := s.ConsumeToken("magic_login", []byte("h2")); err != authx.ErrTokenInvalid {
		t.Fatal("an expired token must not redeem")
	}
}

func TestEmailOTP(t *testing.T) {
	s := newStore(t)
	// Two users can hold OTPs simultaneously (keyed by purpose+email; salted hashes never collide).
	_ = s.CreateEmailOTP("email_otp", "a@x.com", []byte("hashA"), time.Now().Add(time.Minute), 3)
	_ = s.CreateEmailOTP("email_otp", "b@x.com", []byte("hashB"), time.Now().Add(time.Minute), 3)

	// Scoping: A's code must not verify against A's row using B's hash.
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", []byte("hashB")); err != authx.ErrTokenInvalid {
		t.Fatal("a code must be scoped to its own row/hash")
	}
	// Resend replaces (OnConflict upsert on (purpose,email)).
	_ = s.CreateEmailOTP("email_otp", "a@x.com", []byte("hashA2"), time.Now().Add(time.Minute), 3)
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", []byte("hashA")); err != authx.ErrTokenInvalid {
		t.Fatal("the superseded code must be dead")
	}
	if c, err := s.VerifyEmailOTP("email_otp", "a@x.com", []byte("hashA2")); err != nil || c.Email != "a@x.com" {
		t.Fatalf("the latest code must verify: %v", err)
	}
	// Attempt cap: 3 wrong guesses invalidate even the correct code.
	_ = s.CreateEmailOTP("email_otp", "b@x.com", []byte("good"), time.Now().Add(time.Minute), 3)
	for i := 0; i < 3; i++ {
		_, _ = s.VerifyEmailOTP("email_otp", "b@x.com", []byte("bad"))
	}
	if _, err := s.VerifyEmailOTP("email_otp", "b@x.com", []byte("good")); err != authx.ErrTokenInvalid {
		t.Fatal("the code must be invalidated after the attempt cap")
	}
	// Expired.
	_ = s.CreateEmailOTP("email_otp", "c@x.com", []byte("x"), time.Now().Add(-time.Second), 3)
	if _, err := s.VerifyEmailOTP("email_otp", "c@x.com", []byte("x")); err != authx.ErrTokenInvalid {
		t.Fatal("an expired OTP must not verify")
	}
}

func TestDeleteUser_CascadeAndAuditAnonymization(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("gone@x.com", "Gone")
	_ = s.SetPasswordHash(u.ID, "h", "bcrypt")
	_ = s.AddPasskey(u.ID, authx.Passkey{CredentialID: []byte("c"), Name: "k"})
	_ = s.LinkOAuth(u.ID, "google", "g", "gone@x.com")
	_ = s.CreateToken("magic_login", u.ID, "gone@x.com", []byte("t"), time.Now().Add(time.Minute))
	_ = s.CreateEmailOTP("email_otp", "gone@x.com", []byte("o"), time.Now().Add(time.Minute), 3)
	g, _ := s.CreateGroup("g1", "")
	_ = s.AddUserToGroup(u.ID, g.ID)
	_ = s.SetTOTPSecret(u.ID, "SECRET")
	_ = s.ReplaceRecoveryCodes(u.ID, [][]byte{[]byte("rc")})
	_ = s.RecordSession(authx.SessionRecord{SID: "sid1", Subject: subOf(t, s, u.ID), UserID: u.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	s.RecordAudit(u.ID, "gone@x.com", "203.0.113.9", "password", "login", true, "")

	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySub(u.Sub); err != authx.ErrNoUser {
		t.Fatal("user must be gone")
	}
	if _, _, err := s.PasswordHash(u.ID); err != authx.ErrNoCredential {
		t.Fatal("password must be gone")
	}
	if pks, _ := s.Passkeys(u.ID); len(pks) != 0 {
		t.Fatal("passkeys must be gone")
	}
	if ids, _ := s.OAuthIdentities(u.ID); len(ids) != 0 {
		t.Fatal("oauth must be gone")
	}
	if _, err := s.VerifyEmailOTP("email_otp", "gone@x.com", []byte("o")); err != authx.ErrTokenInvalid {
		t.Fatal("OTPs must be gone")
	}
	if list, _ := s.ListSessionsForUser(u.Sub); len(list) != 0 {
		t.Fatal("sessions must not be listable after delete")
	}
	// REGRESSION (#1): the session must be TOMBSTONED (revoked), not deleted — otherwise IsRevoked reads
	// the absent SID as "not revoked" and the deleted user stays authenticated on other devices.
	if revoked, _ := s.IsRevoked("sid1"); !revoked {
		t.Fatal("a deleted user's session must remain revoked, not vanish (revocation bypass)")
	}
	// Audit rows are RETAINED but their PII is scrubbed (GDPR erasure keeps the forensic count).
	var n int64
	s.db.Model(&LoginAudit{}).Where("user_id = ?", u.ID).Count(&n)
	if n != 1 {
		t.Fatalf("audit row must be retained, count=%d", n)
	}
	var a LoginAudit
	s.db.Where("user_id = ?", u.ID).First(&a)
	if a.Email != "" || a.IP != "" {
		t.Fatalf("audit PII must be anonymized, got email=%q ip=%q", a.Email, a.IP)
	}
}

func subOf(t *testing.T, s *Store, id uint) string {
	t.Helper()
	u, err := s.UserByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return u.Sub
}

func TestDirectoryGroupsAndMembership(t *testing.T) {
	s := newStore(t)
	u1, _ := s.CreateLocalUser("u1@x.com", "U1")
	u2, _ := s.CreateLocalUser("u2@x.com", "U2")
	g, err := s.CreateGroup("admins", "the admins")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupByName("admins"); got == nil || got.ID != g.ID {
		t.Fatal("GroupByName failed")
	}
	if _, err := s.GroupByName("nope"); err != authx.ErrNoGroup {
		t.Fatalf("missing group must be ErrNoGroup, got %v", err)
	}
	_ = s.AddUserToGroup(u1.ID, g.ID)
	_ = s.AddUserToGroup(u1.ID, g.ID) // idempotent
	_ = s.AddUserToGroup(u2.ID, g.ID)
	if gs, _ := s.UserGroups(u1.ID); len(gs) != 1 || gs[0].Name != "admins" {
		t.Fatalf("UserGroups wrong: %+v", gs)
	}
	if members, _ := s.GroupMembers(g.ID); len(members) != 2 {
		t.Fatalf("want 2 members, got %d", len(members))
	}
	_ = s.RemoveUserFromGroup(u2.ID, g.ID)
	if members, _ := s.GroupMembers(g.ID); len(members) != 1 {
		t.Fatal("RemoveUserFromGroup failed")
	}
	// DeleteGroup also clears memberships.
	_ = s.DeleteGroup(g.ID)
	if gs, _ := s.UserGroups(u1.ID); len(gs) != 0 {
		t.Fatal("DeleteGroup must clear memberships")
	}
	if users, _ := s.ListUsers(); len(users) != 2 {
		t.Fatalf("ListUsers want 2, got %d", len(users))
	}
}

func TestSetUserDisabledAndBan(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("a@x.com", "A")
	_ = s.SetUserDisabled(u.ID, true)
	if got, _ := s.UserByID(u.ID); !got.Disabled {
		t.Fatal("disable not reflected")
	}
	until := time.Now().Add(time.Hour).UTC()
	_ = s.SetUserBan(u.ID, true, &until, "spam")
	got, _ := s.UserByID(u.ID)
	if !got.Banned || got.BanReason != "spam" || got.BannedUntil.IsZero() {
		t.Fatalf("ban not reflected: %+v", got)
	}
	_ = s.SetUserBan(u.ID, false, nil, "")
	got, _ = s.UserByID(u.ID)
	if got.Banned || got.BanReason != "" || !got.BannedUntil.IsZero() {
		t.Fatalf("unban must clear all ban fields: %+v", got)
	}
}

func TestAPIKeys(t *testing.T) {
	s := newStore(t)
	k, err := s.CreateAPIKey("ci", []string{"deploy"}, []string{"admin"}, "axk_abc", []byte("hash"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.APIKeyByHash([]byte("hash"))
	if err != nil || got.Name != "ci" || len(got.Scopes) != 1 || got.Scopes[0] != "admin" {
		t.Fatalf("APIKeyByHash wrong: %+v (%v)", got, err)
	}
	if _, err := s.APIKeyByHash([]byte("nope")); err != authx.ErrNoCredential {
		t.Fatalf("missing key must be ErrNoCredential, got %v", err)
	}
	_ = s.TouchAPIKey(k.ID)
	if got, _ := s.APIKeyByHash([]byte("hash")); got.LastUsedAt == nil {
		t.Fatal("TouchAPIKey must stamp LastUsedAt")
	}
	if keys, _ := s.ListAPIKeys(); len(keys) != 1 {
		t.Fatal("ListAPIKeys wrong count")
	}
	_ = s.RevokeAPIKey(k.ID)
	if _, err := s.APIKeyByHash([]byte("hash")); err != authx.ErrNoCredential {
		t.Fatal("revoked key must be gone")
	}
}

func TestTwoFactor(t *testing.T) {
	s := newStore(t)
	u, _ := s.CreateLocalUser("a@x.com", "A")
	if _, err := s.TOTP(u.ID); err != authx.ErrNoCredential {
		t.Fatalf("no TOTP yet must be ErrNoCredential, got %v", err)
	}
	_ = s.SetTOTPSecret(u.ID, "SECRET")
	if info, _ := s.TOTP(u.ID); info.Enabled || info.Secret != "SECRET" {
		t.Fatalf("fresh TOTP must be disabled: %+v", info)
	}
	_ = s.EnableTOTP(u.ID)
	if info, _ := s.TOTP(u.ID); !info.Enabled {
		t.Fatal("EnableTOTP failed")
	}
	// Atomic replay guard: a step only advances forward.
	if ok, _ := s.ClaimTOTPStep(u.ID, 100); !ok {
		t.Fatal("first claim of step 100 must win")
	}
	if ok, _ := s.ClaimTOTPStep(u.ID, 100); ok {
		t.Fatal("re-claiming the same step must fail (replay)")
	}
	if ok, _ := s.ClaimTOTPStep(u.ID, 99); ok {
		t.Fatal("claiming an older step must fail")
	}
	if ok, _ := s.ClaimTOTPStep(u.ID, 101); !ok {
		t.Fatal("claiming a newer step must win")
	}
	// Recovery codes: single-use.
	_ = s.ReplaceRecoveryCodes(u.ID, [][]byte{[]byte("c1"), []byte("c2")})
	if n, _ := s.RecoveryCodesRemaining(u.ID); n != 2 {
		t.Fatalf("want 2 recovery codes, got %d", n)
	}
	if ok, _ := s.ConsumeRecoveryCode(u.ID, []byte("c1")); !ok {
		t.Fatal("valid recovery code must consume")
	}
	if ok, _ := s.ConsumeRecoveryCode(u.ID, []byte("c1")); ok {
		t.Fatal("a recovery code must be single-use")
	}
	if n, _ := s.RecoveryCodesRemaining(u.ID); n != 1 {
		t.Fatalf("want 1 remaining, got %d", n)
	}
	// Disable removes TOTP + recovery codes.
	_ = s.DisableTOTP(u.ID)
	if _, err := s.TOTP(u.ID); err != authx.ErrNoCredential {
		t.Fatal("DisableTOTP must remove the secret")
	}
	if n, _ := s.RecoveryCodesRemaining(u.ID); n != 0 {
		t.Fatal("DisableTOTP must remove recovery codes")
	}
}

func TestSessionStore(t *testing.T) {
	s := newStore(t)
	now := time.Now()
	mk := func(sid string, exp time.Duration) authx.SessionRecord {
		return authx.SessionRecord{SID: sid, Subject: "sub1", UserID: 1, CreatedAt: now, ExpiresAt: now.Add(exp)}
	}
	_ = s.RecordSession(mk("sid1", time.Hour))
	_ = s.RecordSession(mk("sid2", time.Hour))
	_ = s.RecordSession(mk("expired", -time.Second)) // already expired

	if r, _ := s.IsRevoked("sid1"); r {
		t.Fatal("fresh session must not be revoked")
	}
	if r, _ := s.IsRevoked("unknown"); !r {
		t.Fatal("unknown non-empty sid must fail closed (revoked) — recorded sessions are only tombstoned")
	}
	if list, _ := s.ListSessionsForUser("sub1"); len(list) != 2 {
		t.Fatalf("list must exclude the expired session, got %d", len(list))
	}
	_ = s.RevokeSession("sid1")
	if r, _ := s.IsRevoked("sid1"); !r {
		t.Fatal("revoked session must report revoked")
	}
	if list, _ := s.ListSessionsForUser("sub1"); len(list) != 1 || list[0].SID != "sid2" {
		t.Fatalf("revoked session must drop from the list, got %+v", list)
	}
	_ = s.RevokeAllForUser("sub1")
	if list, _ := s.ListSessionsForUser("sub1"); len(list) != 0 {
		t.Fatal("revoke-all must clear the list")
	}
}

// The security-critical account-linking invariant, exercised against real SQL + transactions.
func TestUpsertUserOnLogin_LinkingMatrix(t *testing.T) {
	t.Run("new user created", func(t *testing.T) {
		s := newStore(t)
		u, err := s.UpsertUserOnLogin("oidc:1", "new@x.com", "New", true)
		if err != nil || u.Sub != "oidc:1" || !u.EmailVerified {
			t.Fatalf("new verified login must create a user: %+v %v", u, err)
		}
	})

	t.Run("unverified squatter refused for unproven login", func(t *testing.T) {
		s := newStore(t)
		_, _ = s.CreateLocalUser("victim@x.com", "Squatter") // unverified, non-bootstrap
		if _, err := s.UpsertUserOnLogin("oidc:evil", "victim@x.com", "Attacker", false); err != authx.ErrEmailConflict {
			t.Fatalf("an unproven login onto an unverified squatter must be refused, got %v", err)
		}
	})

	t.Run("verified login reclaims a squatter", func(t *testing.T) {
		s := newStore(t)
		sq, _ := s.CreateLocalUser("victim@x.com", "Squatter")
		_ = s.SetPasswordHash(sq.ID, "squatpw", "bcrypt")
		u, err := s.UpsertUserOnLogin("oidc:victim", "victim@x.com", "Real", true)
		if err != nil || u.Sub != "oidc:victim" || !u.EmailVerified {
			t.Fatalf("a verified login must reclaim the email: %+v %v", u, err)
		}
		// The squatter's credentials must be gone (new clean user, different id).
		if _, _, err := s.PasswordHash(sq.ID); err != authx.ErrNoCredential {
			t.Fatal("the squatter's password must be deleted on reclaim")
		}
	})

	t.Run("verified row rebind refused for unproven login", func(t *testing.T) {
		s := newStore(t)
		_, _ = s.UpsertUserOnLogin("oidc:owner", "owner@x.com", "Owner", true) // verified row
		if _, err := s.UpsertUserOnLogin("oidc:attacker", "owner@x.com", "Attacker", false); err != authx.ErrEmailConflict {
			t.Fatalf("an unproven login must not seize a verified account, got %v", err)
		}
	})

	t.Run("subject-move onto another email is typed ErrEmailConflict", func(t *testing.T) {
		s := newStore(t)
		_, _ = s.UpsertUserOnLogin("oidc:a", "a@x.com", "A", true)
		_, _ = s.UpsertUserOnLogin("oidc:b", "b@x.com", "B", true)
		// B re-logs-in asserting A's email → typed conflict (parity with memory), not a raw DB error.
		if _, err := s.UpsertUserOnLogin("oidc:b", "a@x.com", "B", true); err != authx.ErrEmailConflict {
			t.Fatalf("want ErrEmailConflict, got %v", err)
		}
	})

	t.Run("bootstrap row adopted on first login", func(t *testing.T) {
		s := newStore(t)
		s.db.Create(&User{Sub: "bootstrap:seed", Email: "boot@x.com", Name: "Boot"})
		u, err := s.UpsertUserOnLogin("oidc:boot", "boot@x.com", "Boot", false) // even unverified
		if err != nil || u.Sub != "oidc:boot" {
			t.Fatalf("a bootstrap placeholder must be adopted on first login: %+v %v", u, err)
		}
	})
}
