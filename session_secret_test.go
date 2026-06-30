package authx

import (
	"context"
	"strings"
	"testing"
)

// TestNewRequiresStrongSessionSecret pins the documented "boot fails closed" guarantee: a session
// secret, when set (or when OIDC is configured), must be at least 32 bytes.
func TestNewRequiresStrongSessionSecret(t *testing.T) {
	ctx := context.Background()

	// Provided but too short → fail closed.
	if _, err := New(ctx, Config{SessionSecret: []byte("0123456789abcdef")}); err == nil { // 16 bytes
		t.Fatal("New must reject a SESSION_SECRET shorter than 32 bytes")
	} else if !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("error should name the 32-byte requirement, got: %v", err)
	}

	// OIDC configured but no secret → also fail closed (a secret is required).
	if _, err := New(ctx, Config{Issuer: "https://id.example.com", ClientID: "x"}); err == nil {
		t.Fatal("New must reject OIDC configured without a SESSION_SECRET")
	}

	// Exactly 32 bytes, no OIDC → constructs.
	if a, err := New(ctx, Config{SessionSecret: []byte("0123456789abcdef0123456789abcdef")}); err != nil || a == nil {
		t.Fatalf("a 32-byte secret should be accepted: a=%v err=%v", a, err)
	}

	// No auth configured at all → constructs (no cookies will be minted).
	if a, err := New(ctx, Config{}); err != nil || a == nil {
		t.Fatalf("empty config should construct (auth simply off): a=%v err=%v", a, err)
	}
}
