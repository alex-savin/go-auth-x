package memory

import (
	"testing"

	authx "github.com/alex-savin/go-auth-x"
)

// TestAdoptGateRequiresProof pins the H2 hardening: an existing VERIFIED row must not be rebound to a
// new subject by a login that did NOT prove the email (emailVerified=false). Only a proven login may
// link/rebind. Bootstrap placeholders remain adoptable.
func TestAdoptGateRequiresProof(t *testing.T) {
	// Verified account owned by the real user.
	s := New()
	real, _ := s.UpsertUserOnLogin("oidc:real", "user@x.com", "Real", true)
	if !real.EmailVerified {
		t.Fatal("precondition: row should be verified")
	}

	// An UNPROVEN login (emailVerified=false) with a new subject must be refused, not adopt the row.
	if _, err := s.UpsertUserOnLogin("oidc:attacker", "user@x.com", "Attacker", false); err != authx.ErrEmailConflict {
		t.Fatalf("unproven login onto a verified row: want ErrEmailConflict, got %v", err)
	}
	// The row must be untouched (still bound to the real subject).
	got, _ := s.UserByEmail("user@x.com")
	if got.Sub != "oidc:real" {
		t.Fatalf("verified row was rebound by an unproven login (takeover): sub=%q", got.Sub)
	}

	// A PROVEN login with a new subject legitimately links (rebinds) the verified row.
	if _, err := s.UpsertUserOnLogin("oidc:linked", "user@x.com", "Real", true); err != nil {
		t.Fatalf("proven login should link the verified row: %v", err)
	}
	if got, _ := s.UserByEmail("user@x.com"); got.Sub != "oidc:linked" {
		t.Fatalf("proven login should have rebound the row, got sub=%q", got.Sub)
	}

	// Bootstrap placeholders stay adoptable even by an unproven first login.
	b := New()
	if _, err := b.UpsertUserOnLogin("bootstrap:owner@x.com", "owner@x.com", "Owner", false); err != nil {
		t.Fatalf("seed bootstrap: %v", err)
	}
	if bu, err := b.UpsertUserOnLogin("real-owner", "owner@x.com", "Owner", false); err != nil || bu.Sub != "real-owner" {
		t.Fatalf("bootstrap should be adoptable: user=%+v err=%v", bu, err)
	}
}
