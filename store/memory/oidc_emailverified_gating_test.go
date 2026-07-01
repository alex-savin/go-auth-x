package memory

import (
	"context"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
)

// TestOIDCEmailVerifiedGatingViaAuthorizer adversarially verifies that the OIDC
// email_verified claim threads through the *reference Authorizer* (Store.Authorizer().
// Authorize) and gates the safe account-linking rule — i.e. the rule uses id.EmailVerified,
// not a hardcoded true.
//
// The claim to break: an UNVERIFIED OIDC identity must NOT silently take over / adopt an
// unverified local squatter. It must be refused with ErrEmailConflict. Only a VERIFIED
// identity may reclaim the squatter's email.
func TestOIDCEmailVerifiedGatingViaAuthorizer(t *testing.T) {
	ctx := context.Background()

	// ---- Case 1: UNVERIFIED OIDC identity must NOT take over an unverified squatter. ----
	s := New()
	squatter, err := s.CreateLocalUser("victim@example.com", "Squatter")
	if err != nil {
		t.Fatalf("seed squatter: %v", err)
	}
	// Sanity: CreateLocalUser produces an UNVERIFIED, local (non-bootstrap) row.
	if squatter.EmailVerified {
		t.Fatalf("precondition: CreateLocalUser should be unverified, got verified")
	}
	_ = s.SetPasswordHash(squatter.ID, "squatter-bcrypt-hash", "bcrypt")

	az := s.Authorizer()

	_, err = az.Authorize(ctx, authx.Identity{
		Subject:       "oidc:abc",
		Email:         "victim@example.com",
		Name:          "Real Victim",
		EmailVerified: false, // the OIDC IdP did NOT prove this email
	})
	if err != authx.ErrEmailConflict {
		t.Fatalf("UNVERIFIED oidc identity colliding with unverified squatter: "+
			"want ErrEmailConflict (no takeover), got %v", err)
	}

	// The squatter must be UNTOUCHED: same id, still the local sub, still has its password.
	got, gerr := s.UserByEmail("victim@example.com")
	if gerr != nil {
		t.Fatalf("squatter should still exist after refused takeover: %v", gerr)
	}
	if got.ID != squatter.ID {
		t.Fatalf("squatter id changed (silent takeover!): was %d now %d", squatter.ID, got.ID)
	}
	if got.Sub == "oidc:abc" {
		t.Fatalf("squatter Sub was adopted by unverified oidc identity (takeover!): %q", got.Sub)
	}
	if got.Sub != squatter.Sub {
		t.Fatalf("squatter Sub mutated: was %q now %q", squatter.Sub, got.Sub)
	}
	if _, _, e := s.PasswordHash(squatter.ID); e != nil {
		t.Fatalf("squatter password should survive a refused takeover, got err %v", e)
	}
	// And the attacker's oidc sub must NOT resolve to any user.
	if u, e := s.UserBySub("oidc:abc"); e == nil {
		t.Fatalf("oidc:abc must not resolve to a user after refusal, got %+v", u)
	}

	// ---- Case 2: VERIFIED OIDC identity reclaims the email; row Sub becomes oidc:abc. ----
	_, err = az.Authorize(ctx, authx.Identity{
		Subject:       "oidc:abc",
		Email:         "victim@example.com",
		Name:          "Real Victim",
		EmailVerified: true, // the IdP proved the email this time
	})
	if err != nil {
		t.Fatalf("VERIFIED oidc identity should reclaim the email, got err %v", err)
	}
	reclaimed, rerr := s.UserByEmail("victim@example.com")
	if rerr != nil {
		t.Fatalf("user should exist after verified reclaim: %v", rerr)
	}
	if reclaimed.Sub != "oidc:abc" {
		t.Fatalf("row Sub should become oidc:abc after verified reclaim, got %q", reclaimed.Sub)
	}
	if !reclaimed.EmailVerified {
		t.Fatalf("reclaimed row should be marked verified")
	}
	if bySub, e := s.UserBySub("oidc:abc"); e != nil || bySub.ID != reclaimed.ID {
		t.Fatalf("oidc:abc should now resolve to the reclaimed row: err=%v user=%+v", e, bySub)
	}
	// Reclaim is a delete-then-recreate cascade: the squatter's stale password must be gone.
	if _, _, e := s.PasswordHash(squatter.ID); e != authx.ErrNoCredential {
		t.Fatalf("after reclaim the old squatter credentials must be cascaded away, got %v", e)
	}

	// ---- Case 3 (sanity): EmailVerified=false for a BRAND-NEW email still creates a user. ----
	fresh := New()
	faz := fresh.Authorizer()
	if _, err := faz.Authorize(ctx, authx.Identity{
		Subject:       "oidc:new",
		Email:         "brandnew@example.com",
		Name:          "New Person",
		EmailVerified: false,
	}); err != nil {
		t.Fatalf("unverified identity for a fresh email should still create a user, got %v", err)
	}
	nu, nerr := fresh.UserByEmail("brandnew@example.com")
	if nerr != nil {
		t.Fatalf("fresh unverified user should have been created: %v", nerr)
	}
	if nu.Sub != "oidc:new" {
		t.Fatalf("fresh user Sub: want oidc:new, got %q", nu.Sub)
	}
	if nu.EmailVerified {
		t.Fatalf("fresh user created from unverified identity should be UNVERIFIED, got verified")
	}
}
