package memory

import (
	"testing"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the in-memory store satisfies the interface.
var _ authx.CredentialStore = (*Store)(nil)

// TestLinkingRule is the account-takeover regression test: an unverified, non-bootstrap squatter
// must never be adopted by a later verified login; bootstrap placeholders and verified rows may be.
func TestLinkingRule(t *testing.T) {
	// 1. Takeover attempt: attacker pre-signs-up victim@x (unverified local row).
	s := New()
	if _, err := s.CreateLocalUser("victim@x.com", "attacker"); err != nil {
		t.Fatalf("seed squatter: %v", err)
	}
	// Victim logs in via OIDC (verified). MUST refuse, not adopt.
	if _, err := s.UpsertUserOnLogin("idp-sub-real", "victim@x.com", "Victim", true); err != authx.ErrEmailConflict {
		t.Fatalf("squatter takeover not blocked: got err=%v, want ErrEmailConflict", err)
	}

	// 2. Bootstrap adopt: an operator-seeded bootstrap: placeholder IS adopted on first real login.
	b := New()
	if _, err := b.UpsertUserOnLogin("bootstrap:owner@x.com", "owner@x.com", "Owner", false); err != nil {
		t.Fatalf("seed bootstrap: %v", err)
	}
	u, err := b.UpsertUserOnLogin("real-owner-sub", "owner@x.com", "Owner", true)
	if err != nil || u.Sub != "real-owner-sub" {
		t.Fatalf("bootstrap adopt failed: err=%v user=%+v", err, u)
	}

	// 3. Verified-row adopt: a verified account re-resolved under a new subject IS linked.
	v := New()
	au, _ := v.CreateLocalUser("dual@x.com", "Dual")
	_ = v.SetEmailVerified(au.ID, true)
	if _, err := v.UpsertUserOnLogin("new-sub-for-dual", "dual@x.com", "Dual", true); err != nil {
		t.Fatalf("verified-row link should succeed: %v", err)
	}
}

// TestCredentialRoundTrip exercises the password + single-use token paths.
func TestCredentialRoundTrip(t *testing.T) {
	s := New()
	u, err := s.CreateLocalUser("a@b.com", "A")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := s.PasswordHash(u.ID); err != authx.ErrNoCredential {
		t.Fatalf("want ErrNoCredential, got %v", err)
	}
	if err := s.SetPasswordHash(u.ID, "hash", "bcrypt"); err != nil {
		t.Fatalf("set hash: %v", err)
	}
	if h, algo, err := s.PasswordHash(u.ID); err != nil || h != "hash" || algo != "bcrypt" {
		t.Fatalf("password round-trip: %q %q %v", h, algo, err)
	}
}
