package memory

import (
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

func TestEmailOTP_SuccessAndScoping(t *testing.T) {
	s := New()
	good := []byte("hash-of-correct-code")
	if err := s.CreateEmailOTP("email_otp", "a@x.com", good, time.Now().Add(time.Minute), 3); err != nil {
		t.Fatal(err)
	}
	// Wrong email → no match (scoping), even with the right hash.
	if _, err := s.VerifyEmailOTP("email_otp", "b@x.com", good); err != authx.ErrTokenInvalid {
		t.Fatalf("code must be scoped to its email, got %v", err)
	}
	// Right email + hash → claim, and the code is single-use.
	claim, err := s.VerifyEmailOTP("email_otp", "a@x.com", good)
	if err != nil || claim == nil || claim.Email != "a@x.com" {
		t.Fatalf("valid code must verify, got claim=%v err=%v", claim, err)
	}
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", good); err != authx.ErrTokenInvalid {
		t.Fatal("a consumed code must not verify again")
	}
}

func TestEmailOTP_AttemptCap(t *testing.T) {
	s := New()
	good := []byte("good")
	bad := []byte("bad!")
	if err := s.CreateEmailOTP("email_otp", "a@x.com", good, time.Now().Add(time.Minute), 3); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", bad); err != authx.ErrTokenInvalid {
			t.Fatalf("wrong code attempt %d must fail", i+1)
		}
	}
	// After maxAttempts wrong tries the code is invalidated — even the CORRECT code no longer works.
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", good); err != authx.ErrTokenInvalid {
		t.Fatal("code must be invalidated once the attempt cap is exceeded")
	}
}

func TestEmailOTP_Expired(t *testing.T) {
	s := New()
	good := []byte("good")
	if err := s.CreateEmailOTP("email_otp", "a@x.com", good, time.Now().Add(-time.Second), 3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", good); err != authx.ErrTokenInvalid {
		t.Fatal("an expired code must not verify")
	}
}

func TestSessionStore_RecordRevokeList(t *testing.T) {
	s := New()
	now := time.Now()
	rec := func(sid string) authx.SessionRecord {
		return authx.SessionRecord{SID: sid, Subject: "sub1", UserID: "1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	_ = s.RecordSession(rec("sid1"))
	_ = s.RecordSession(rec("sid2"))

	if r, _ := s.IsRevoked("sid1"); r {
		t.Fatal("a fresh session must not be revoked")
	}
	if r, _ := s.IsRevoked("unknown"); !r {
		t.Fatal("an unknown non-empty sid must fail closed (revoked) — recorded sessions are only tombstoned")
	}
	if list, _ := s.ListSessionsForUser("sub1"); len(list) != 2 {
		t.Fatalf("want 2 active sessions, got %d", len(list))
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
		t.Fatalf("revoke-all must clear the list, got %d", len(list))
	}
}

func TestDeleteUser_Cascade(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("gone@x.com", "Gone")
	_ = s.SetPasswordHash(u.ID, "h", "bcrypt")
	_ = s.LinkOAuth(u.ID, "google", "g-sub", "gone@x.com")
	_ = s.RecordSession(authx.SessionRecord{SID: "s1", Subject: u.Sub, UserID: u.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})

	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySub(u.Sub); err != authx.ErrNoUser {
		t.Fatal("user must be gone")
	}
	if _, _, err := s.PasswordHash(u.ID); err != authx.ErrNoCredential {
		t.Fatal("password must be gone")
	}
	if ids, _ := s.OAuthIdentities(u.ID); len(ids) != 0 {
		t.Fatal("oauth links must be gone")
	}
	if list, _ := s.ListSessionsForUser(u.Sub); len(list) != 0 {
		t.Fatal("sessions must not be listable after delete")
	}
	// REGRESSION (#1): session must be tombstoned (revoked), not deleted.
	if revoked, _ := s.IsRevoked("s1"); !revoked {
		t.Fatal("a deleted user's session must remain revoked, not vanish")
	}
}

func TestDeleteUser_AnonymizesAuditByUserID(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("old@x.com", "U")
	s.RecordAudit(u.ID, "old@x.com", "1.2.3.4", "password", "login", false, "") // failure under old email
	_ = s.SetEmail(u.ID, "new@x.com")                                           // user later changes email
	if n, _ := s.RecentFailures("old@x.com", time.Now().Add(-time.Hour)); n != 1 {
		t.Fatalf("precondition: the old-email failure should be counted, got %d", n)
	}
	_ = s.DeleteUser(u.ID)
	// Anonymized by userID, so the row written under the OLD email is scrubbed too (#13).
	if n, _ := s.RecentFailures("old@x.com", time.Now().Add(-time.Hour)); n != 0 {
		t.Fatalf("audit rows must be anonymized by userID after delete, still counted %d", n)
	}
}

func TestAddPasskey_DuplicateCredential(t *testing.T) {
	s := New()
	u1, _ := s.CreateLocalUser("a@x.com", "A")
	u2, _ := s.CreateLocalUser("b@x.com", "B")
	if err := s.AddPasskey(u1.ID, authx.Passkey{CredentialID: []byte("dup")}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPasskey(u2.ID, authx.Passkey{CredentialID: []byte("dup")}); err == nil {
		t.Fatal("a globally-duplicate credential ID must be rejected (parity with gormstore)")
	}
}

func TestCreateGroup_DuplicateName(t *testing.T) {
	s := New()
	if _, err := s.CreateGroup("admins", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup("admins", ""); err == nil {
		t.Fatal("a duplicate group name must be rejected (parity with gormstore)")
	}
}

func TestPeekTokenDoesNotConsume(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@x.com", "A")
	_ = s.CreateToken("password_reset", u.ID, "a@x.com", []byte("h"), time.Now().Add(time.Minute))
	if _, err := s.PeekToken("password_reset", []byte("h")); err != nil {
		t.Fatalf("peek must succeed without consuming: %v", err)
	}
	if _, err := s.PeekToken("password_reset", []byte("h")); err != nil {
		t.Fatal("second peek must still succeed")
	}
	if _, err := s.ConsumeToken("password_reset", []byte("h")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekToken("password_reset", []byte("h")); err != authx.ErrTokenInvalid {
		t.Fatal("peek after consume must be invalid")
	}
}

func TestSetEmail_Conflict(t *testing.T) {
	s := New()
	_, _ = s.CreateLocalUser("a@x.com", "A")
	b, _ := s.CreateLocalUser("b@x.com", "B")
	if err := s.SetEmail(b.ID, "a@x.com"); err != authx.ErrEmailConflict {
		t.Fatalf("changing to a taken email must conflict, got %v", err)
	}
	if err := s.SetEmail(b.ID, "c@x.com"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserBySub(b.Sub)
	if got.Email != "c@x.com" || !got.EmailVerified {
		t.Fatalf("SetEmail must update + verify, got %+v", got)
	}
}

func TestOAuthUnlinkAndList(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@x.com", "A")
	_ = s.LinkOAuth(u.ID, "google", "g1", "a@x.com")
	_ = s.LinkOAuth(u.ID, "github", "h1", "a@x.com")
	ids, _ := s.OAuthIdentities(u.ID)
	if len(ids) != 2 || ids[0] != "github" || ids[1] != "google" {
		t.Fatalf("want [github google], got %v", ids)
	}
	_ = s.UnlinkOAuth(u.ID, "google")
	if ids, _ := s.OAuthIdentities(u.ID); len(ids) != 1 || ids[0] != "github" {
		t.Fatalf("unlink must leave [github], got %v", ids)
	}
}

func TestEmailOTP_ReplaceOnResend(t *testing.T) {
	s := New()
	first := []byte("first")
	second := []byte("second")
	_ = s.CreateEmailOTP("email_otp", "a@x.com", first, time.Now().Add(time.Minute), 3)
	_ = s.CreateEmailOTP("email_otp", "a@x.com", second, time.Now().Add(time.Minute), 3) // resend replaces
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", first); err != authx.ErrTokenInvalid {
		t.Fatal("the superseded code must no longer verify")
	}
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", second); err != nil {
		t.Fatalf("the latest code must verify, got %v", err)
	}
}

func TestEmailOTP_SingleAttempt(t *testing.T) {
	s := New()
	_ = s.CreateEmailOTP("email_otp", "a@x.com", []byte("good"), time.Now().Add(time.Minute), 1)
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", []byte("bad")); err != authx.ErrTokenInvalid {
		t.Fatal("wrong code fails")
	}
	// maxAttempts=1: the single wrong guess already consumed the code.
	if _, err := s.VerifyEmailOTP("email_otp", "a@x.com", []byte("good")); err != authx.ErrTokenInvalid {
		t.Fatal("with maxAttempts=1 the code must be dead after one guess")
	}
}

func TestDeleteUser_Idempotent(t *testing.T) {
	s := New()
	if err := s.DeleteUser("999"); err != nil {
		t.Fatalf("deleting an absent user must be a no-op, got %v", err)
	}
	u, _ := s.CreateLocalUser("a@x.com", "A")
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatalf("second delete must be a no-op, got %v", err)
	}
}

func TestUnlinkOAuth_Nonexistent(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@x.com", "A")
	if err := s.UnlinkOAuth(u.ID, "google"); err != nil {
		t.Fatalf("unlinking a provider that isn't linked must be a no-op, got %v", err)
	}
}

func TestRenamePasskey_WrongUser(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@x.com", "A")
	_ = s.AddPasskey(u.ID, authx.Passkey{CredentialID: []byte("c"), Name: "keep"})
	pks, _ := s.Passkeys(u.ID)
	_ = s.RenamePasskey("999", pks[0].ID, "hijack") // different user (u.ID is "1")
	pks, _ = s.Passkeys(u.ID)
	if pks[0].Name != "keep" {
		t.Fatalf("another user must not rename this passkey, got %q", pks[0].Name)
	}
}

func TestSetEmail_SameAddress(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@x.com", "A")
	if err := s.SetEmail(u.ID, "a@x.com"); err != nil {
		t.Fatalf("setting the same email must not self-conflict, got %v", err)
	}
}

func TestRenamePasskeyAndBan(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("a@x.com", "A")
	_ = s.AddPasskey(u.ID, authx.Passkey{CredentialID: []byte("c"), Name: "old"})
	pks, _ := s.Passkeys(u.ID)
	_ = s.RenamePasskey(u.ID, pks[0].ID, "new")
	pks, _ = s.Passkeys(u.ID)
	if pks[0].Name != "new" {
		t.Fatalf("rename failed, got %q", pks[0].Name)
	}
	until := time.Now().Add(time.Hour)
	_ = s.SetUserBan(u.ID, true, &until, "spam")
	got, _ := s.UserBySub(u.Sub)
	if !got.Banned || got.BanReason != "spam" {
		t.Fatalf("ban not reflected: %+v", got)
	}
	_ = s.SetUserBan(u.ID, false, nil, "")
	got, _ = s.UserBySub(u.Sub)
	if got.Banned {
		t.Fatal("unban not reflected")
	}
}
