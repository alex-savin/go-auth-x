package authx

import (
	"testing"
	"time"
)

// TestSignJWTRefusesWeakSecret pins H1: signing fails closed for a short/empty secret, so a
// misconfigured local-auth deployment can never mint cookies forgeable under a known empty key.
func TestSignJWTRefusesWeakSecret(t *testing.T) {
	for _, secret := range [][]byte{nil, []byte(""), []byte("too-short")} {
		if _, err := mintSession(secret, "sub", "e@x.com", "N", "", "", nil, time.Now(), sessionTTL); err == nil {
			t.Fatalf("mintSession must fail for a secret of len %d", len(secret))
		}
	}
	// A 32-byte secret signs fine.
	if _, err := mintSession([]byte("0123456789abcdef0123456789abcdef"), "sub", "e@x.com", "N", "", "", nil, time.Now(), sessionTTL); err != nil {
		t.Fatalf("a 32-byte secret should sign: %v", err)
	}
}

// TestSanitizeNextRejectsBackslash pins M1: "/\evil.com" is scheme-relative in browsers and must be
// rejected like "//evil.com".
func TestSanitizeNextRejectsBackslash(t *testing.T) {
	for _, bad := range []string{"//evil.com", "/\\evil.com", "\\\\evil.com", "https://evil.com", ""} {
		if got := sanitizeNext(bad); got != "/" {
			t.Fatalf("sanitizeNext(%q) = %q, want \"/\"", bad, got)
		}
	}
	for _, ok := range []string{"/dashboard", "/a/b?c=d"} {
		if got := sanitizeNext(ok); got != ok {
			t.Fatalf("sanitizeNext(%q) = %q, want unchanged", ok, got)
		}
	}
}

// TestIsSocialCallbackCSRFExempt pins H3: a social provider callback (Apple's cross-site form_post)
// is recognized as CSRF-exempt, while ordinary state-changing paths are not.
func TestIsSocialCallbackCSRFExempt(t *testing.T) {
	exempt := []string{"/auth/social/apple/callback", "/auth/social/google/callback", "/auth/social/gitlab/callback"}
	for _, p := range exempt {
		if !isSocialCallback(p) {
			t.Fatalf("%q should be treated as a social callback (CSRF-exempt)", p)
		}
	}
	for _, p := range []string{"/auth/social/apple/login", "/api/account/password", "/auth/reauth", "/auth/2fa/disable"} {
		if isSocialCallback(p) {
			t.Fatalf("%q must NOT be CSRF-exempt", p)
		}
	}
}
