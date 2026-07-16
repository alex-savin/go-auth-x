package memory

import (
	"crypto/sha256"
	"errors"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
)

func TestTwoFactorStore_RoundTrip(t *testing.T) {
	s := New()

	// No TOTP yet.
	if _, err := s.TOTP("1"); !errors.Is(err, authx.ErrNoCredential) {
		t.Fatalf("TOTP on a fresh user should be ErrNoCredential, got %v", err)
	}

	// Enroll (pending) → enable.
	if err := s.SetTOTPSecret("1", "SECRET1"); err != nil {
		t.Fatal(err)
	}
	if info, _ := s.TOTP("1"); info == nil || info.Secret != "SECRET1" || info.Enabled {
		t.Fatalf("after SetTOTPSecret: pending secret expected, got %+v", info)
	}
	_ = s.EnableTOTP("1")
	_ = s.SetTOTPLastStep("1", 42)
	if info, _ := s.TOTP("1"); !info.Enabled || info.LastStep != 42 {
		t.Fatalf("after enable + lastStep: %+v", info)
	}

	// (re)enroll resets enabled + lastStep.
	_ = s.SetTOTPSecret("1", "SECRET2")
	if info, _ := s.TOTP("1"); info.Secret != "SECRET2" || info.Enabled || info.LastStep != 0 {
		t.Fatalf("re-enroll should reset: %+v", info)
	}
	_ = s.EnableTOTP("1")

	// Recovery codes: single-use.
	h := func(c string) []byte { x := sha256.Sum256([]byte(c)); return x[:] }
	if err := s.ReplaceRecoveryCodes("1", [][]byte{h("aaa"), h("bbb")}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.RecoveryCodesRemaining("1"); n != 2 {
		t.Fatalf("remaining = %d, want 2", n)
	}
	if used, _ := s.ConsumeRecoveryCode("1", h("aaa")); !used {
		t.Fatal("valid recovery code should consume")
	}
	if used, _ := s.ConsumeRecoveryCode("1", h("aaa")); used {
		t.Fatal("recovery code must be single-use")
	}
	if n, _ := s.RecoveryCodesRemaining("1"); n != 1 {
		t.Fatalf("remaining after consume = %d, want 1", n)
	}

	// Disable clears both TOTP + recovery codes.
	_ = s.DisableTOTP("1")
	if _, err := s.TOTP("1"); !errors.Is(err, authx.ErrNoCredential) {
		t.Fatal("disable should remove the TOTP credential")
	}
	if n, _ := s.RecoveryCodesRemaining("1"); n != 0 {
		t.Fatalf("disable should clear recovery codes, got %d", n)
	}
}
