package memory

import (
	"testing"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the in-memory store satisfies the interface.
var _ authx.CredentialStore = (*Store)(nil)

// TestLinkingRule is the account-takeover regression test: an unverified, non-bootstrap squatter is
// never ADOPTED. A verified login RECLAIMS the email (squatter deleted, fresh user); an unverified
// login is refused. Bootstrap placeholders and already-verified rows are adopted/linked.
func TestLinkingRule(t *testing.T) {
	// 1a. Reclaim: attacker pre-signs-up victim@x (unverified). Victim's VERIFIED OIDC login must
	// reclaim the email — a new user under the IdP sub, with the squatter (and its creds) gone.
	s := New()
	atk, _ := s.CreateLocalUser("victim@x.com", "attacker")
	_ = s.SetPasswordHash(atk.ID, "attacker-hash", "bcrypt")
	u, err := s.UpsertUserOnLogin("idp-sub-real", "victim@x.com", "Victim", true)
	if err != nil || u.Sub != "idp-sub-real" || u.ID == atk.ID {
		t.Fatalf("verified login should reclaim the email: err=%v user=%+v (squatter id %d)", err, u, atk.ID)
	}
	if _, _, e := s.PasswordHash(atk.ID); e != authx.ErrNoCredential {
		t.Fatalf("squatter credentials should be gone after reclaim, got %v", e)
	}

	// 1b. An UNVERIFIED incoming login colliding with an unverified squatter is still refused.
	s2 := New()
	_, _ = s2.CreateLocalUser("dup@x.com", "first")
	if _, err := s2.UpsertUserOnLogin("local:second", "dup@x.com", "second", false); err != authx.ErrEmailConflict {
		t.Fatalf("unverified collision: want ErrEmailConflict, got %v", err)
	}

	// 2. Bootstrap adopt: an operator-seeded bootstrap: placeholder IS adopted on first real login.
	b := New()
	if _, err := b.UpsertUserOnLogin("bootstrap:owner@x.com", "owner@x.com", "Owner", false); err != nil {
		t.Fatalf("seed bootstrap: %v", err)
	}
	bu, berr := b.UpsertUserOnLogin("real-owner-sub", "owner@x.com", "Owner", true)
	if berr != nil || bu.Sub != "real-owner-sub" {
		t.Fatalf("bootstrap adopt failed: err=%v user=%+v", berr, bu)
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

// TestOAuthLink exercises the social-identity natural key (provider, subject).
func TestOAuthLink(t *testing.T) {
	s := New()
	u, _ := s.CreateLocalUser("g@x.com", "G")
	if _, err := s.UserByOAuth("google", "sub-123"); err != authx.ErrNoUser {
		t.Fatalf("unlinked lookup: want ErrNoUser, got %v", err)
	}
	if err := s.LinkOAuth(u.ID, "google", "sub-123", "g@x.com"); err != nil {
		t.Fatalf("link: %v", err)
	}
	got, err := s.UserByOAuth("google", "sub-123")
	if err != nil || got.ID != u.ID {
		t.Fatalf("linked lookup: err=%v user=%+v", err, got)
	}
}
