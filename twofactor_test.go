package authx

import (
	"testing"
	"time"
)

// fakeTOTP is a minimal in-test TwoFactorStore (avoids an import cycle with store/memory).
type fakeTOTP struct {
	info  *TOTPInfo
	recov map[string]bool
}

func (f *fakeTOTP) TOTP(string) (*TOTPInfo, error) {
	if f.info == nil {
		return nil, ErrNoCredential
	}
	cp := *f.info
	return &cp, nil
}
func (f *fakeTOTP) SetTOTPSecret(_ string, s string) error   { f.info = &TOTPInfo{Secret: s}; return nil }
func (f *fakeTOTP) EnableTOTP(string) error                  { f.info.Enabled = true; return nil }
func (f *fakeTOTP) DisableTOTP(string) error                 { f.info, f.recov = nil, nil; return nil }
func (f *fakeTOTP) SetTOTPLastStep(_ string, s uint64) error { f.info.LastStep = s; return nil }
func (f *fakeTOTP) ClaimTOTPStep(_ string, s uint64) (bool, error) {
	if f.info == nil {
		return false, ErrNoCredential
	}
	if s <= f.info.LastStep {
		return false, nil
	}
	f.info.LastStep = s
	return true, nil
}
func (f *fakeTOTP) ReplaceRecoveryCodes(_ string, hs [][]byte) error {
	f.recov = map[string]bool{}
	for _, h := range hs {
		f.recov[string(h)] = true
	}
	return nil
}
func (f *fakeTOTP) ConsumeRecoveryCode(_ string, h []byte) (bool, error) {
	if f.recov[string(h)] {
		delete(f.recov, string(h))
		return true, nil
	}
	return false, nil
}
func (f *fakeTOTP) RecoveryCodesRemaining(string) (int, error) { return len(f.recov), nil }

func TestVerifySecondFactor_TOTPReplayAndRecovery(t *testing.T) {
	f := &fakeTOTP{}
	a := &Authenticator{twoFactor: f}
	secret, _ := newTOTPSecret()
	_ = f.SetTOTPSecret("1", secret)
	_ = f.EnableTOTP("1")

	raw, _ := b32.DecodeString(secret)
	now := time.Now()
	step := uint64(now.Unix()) / totpPeriod
	code := hotp(raw, step)

	// A valid current TOTP verifies and advances the replay guard.
	info, _ := f.TOTP("1")
	if !a.verifySecondFactor("1", info, code) {
		t.Fatal("a valid current TOTP should verify")
	}
	info2, _ := f.TOTP("1")
	if info2.LastStep != step {
		t.Fatalf("lastStep should advance to %d, got %d", step, info2.LastStep)
	}
	// Replaying the same code (same step) is now rejected.
	if a.verifySecondFactor("1", info2, code) {
		t.Fatal("a replayed TOTP (same step) must be rejected")
	}

	// Recovery codes are single-use.
	codes, hashes, _ := newRecoveryCodes(3)
	_ = f.ReplaceRecoveryCodes("1", hashes)
	info3, _ := f.TOTP("1")
	if !a.verifySecondFactor("1", info3, codes[0]) {
		t.Fatal("a valid recovery code should verify")
	}
	if a.verifySecondFactor("1", info3, codes[0]) {
		t.Fatal("a recovery code must be single-use")
	}
	if !a.verifySecondFactor("1", info3, codes[1]) {
		t.Fatal("a different recovery code should still work")
	}
	// A bad code fails.
	if a.verifySecondFactor("1", info3, "000000") {
		t.Fatal("a wrong code must not verify")
	}
}

func TestPendingCookieRoundTrip(t *testing.T) {
	a := &Authenticator{cfg: Config{SessionSecret: []byte("0123456789abcdef0123456789abcdef")}}
	tok, err := a.mintPending(Identity{Subject: "local:u1", Email: "u@x.com", Name: "U", Groups: []string{"admins"}}, "owner", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := a.parsePending(tok)
	if err != nil || pc.Subject != "local:u1" || pc.Email != "u@x.com" || pc.Role != "owner" || !pc.Remember {
		t.Fatalf("pending round-trip wrong: %+v err=%v", pc, err)
	}
	if len(pc.Groups) != 1 || pc.Groups[0] != "admins" {
		t.Fatalf("groups not preserved: %v", pc.Groups)
	}
	// A tampered token is rejected.
	if _, err := a.parsePending(tok + "x"); err == nil {
		t.Fatal("a tampered pending token must be rejected")
	}
	// A different secret can't verify it.
	b := &Authenticator{cfg: Config{SessionSecret: []byte("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")}}
	if _, err := b.parsePending(tok); err == nil {
		t.Fatal("the pending token must not verify under a different secret")
	}
}

// TestTokenAudienceSegregation pins the fix for the token-confusion bug: a 2FA-pending token (first
// factor only) MUST NOT be accepted in the session-cookie slot — otherwise it bypasses the 2nd factor.
func TestTokenAudienceSegregation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a := &Authenticator{cfg: Config{SessionSecret: secret}}

	pending, err := a.mintPending(Identity{Subject: "local:u1", Email: "u@x.com"}, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The pending token must NOT parse as a session (wrong audience).
	if _, err := parseSession(secret, pending); err == nil {
		t.Fatal("a 2fa-pending token must be rejected as a session cookie (2FA bypass)")
	}
	// And a real session token must NOT parse as a pending token.
	session, _ := mintSession(secret, "local:u1", "u@x.com", "U", "", "", nil, time.Now(), sessionTTL)
	if _, err := a.parsePending(session); err == nil {
		t.Fatal("a session token must be rejected as a 2fa-pending token")
	}
	// The session token parses correctly as a session.
	if sc, err := parseSession(secret, session); err != nil || sc.Subject != "local:u1" {
		t.Fatalf("a session token should parse as a session: %v", err)
	}
}
