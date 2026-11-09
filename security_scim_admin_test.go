package authx_test

// Regression tests for the 2026-11 security audit: provisioning sources asserting emails (C2, C3), the
// owner check (H3), org-bound keys on global surfaces, and reset links after an email change (M5).

import (
	"context"
	"crypto/sha256"
	"net/http"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/scim"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// A customer's SCIM never makes an address verified, can't re-point a mailbox-proven account's email,
// and can't pull such an account back into the org — so it can't stand up an account as anyone.
func TestOrgSCIMCantAssertVerifiedEmails(t *testing.T) {
	a, s, m := newOrgAuth(t)
	org := seedOrg(t, s, "acme", nil)
	key := orgScimKey(t, s, org.ID, "scim-acme")
	view, _ := authx.NewOrgScopedDirectory(s, s, org.ID)
	srv := scim.NewServer(view, func(tok string) bool { return a.ValidateOrgAPIKeyScope(tok, "scim", org.ID) }).Handler()

	// Provisioning an address — even the owner's — doesn't make it an owner session.
	w := scimDo(t, srv, key, "POST", "/Users", `{"userName":"boss","emails":[{"value":"owner@example.com"}]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body.String())
	}
	if u, _ := s.UserByEmail("owner@example.com"); u.EmailVerified {
		t.Fatal("a customer-provisioned address must stay unverified")
	}

	// A user who proves their mailbox owns the account from then on.
	w = scimDo(t, srv, key, "POST", "/Users", `{"userName":"jane","emails":[{"value":"jane@acme.com"}]}`)
	id := decode(t, w)["id"].(string)
	c := newClient(t, a)
	c.do("POST", "/auth/email/request", map[string]any{"email": "jane@acme.com"})
	c.do("GET", "/auth/email/login?token="+tokenRe.FindStringSubmatch(m.waitFor(t, "/auth/email/login").text)[1], nil)
	if u, _ := s.UserByID(id); !u.EmailVerified {
		t.Fatal("the magic link must verify the address")
	}
	if w := scimDo(t, srv, key, "PUT", "/Users/"+id, `{"userName":"jane","emails":[{"value":"someone-else@x.com"}]}`); w.Code != http.StatusConflict {
		t.Fatalf("re-pointing a proven account's email = %d, want 409", w.Code)
	}
	if u, _ := s.UserByID(id); u.Email != "jane@acme.com" {
		t.Fatalf("email changed to %q", u.Email)
	}
	// Deprovisioned, it can't be pulled back in by re-provisioning (existing users join by invite).
	if w := scimDo(t, srv, key, "DELETE", "/Users/"+id, ""); w.Code != http.StatusNoContent {
		t.Fatalf("deprovision = %d", w.Code)
	}
	if w := scimDo(t, srv, key, "POST", "/Users", `{"userName":"jane","emails":[{"value":"jane@acme.com"}]}`); w.Code != http.StatusConflict {
		t.Fatalf("re-adopting a proven account = %d, want 409", w.Code)
	}
}

// The owner is the live, verified account with OWNER_EMAIL — not a cookie's claim, and compared
// exactly (a Unicode case-fold alias of the address is another account).
func TestAdminOwnerIsTheLiveVerifiedAccount(t *testing.T) {
	a, s, _ := newTestAuth(t)
	owner := seedUser(t, s, "owner@example.com", "owner-password-1", true)
	c := newClient(t, a)
	c.login("owner@example.com", "owner-password-1")
	if w := c.do("GET", "/auth/admin/users", nil); w.Code != http.StatusOK {
		t.Fatalf("owner session = %d", w.Code)
	}
	if err := s.SetEmail(owner.ID, "former-owner@example.com"); err != nil {
		t.Fatal(err)
	}
	if w := c.do("GET", "/auth/admin/users", nil); w.Code == http.StatusOK {
		t.Fatal("a session whose account no longer has OWNER_EMAIL must not be the owner")
	}
}

// The owner check doesn't Unicode-fold: "opſ@…" (U+017F, which folds to "s" but is a different
// address and a different account) is not the owner "ops@…".
func TestAdminOwnerCheckDoesNotFold(t *testing.T) {
	store := memory.New()
	a, err := authx.New(context.Background(), authx.Config{
		SessionSecret: []byte(testSecret), AppURL: "https://app.example.com", OwnerEmail: "ops@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	a.SetCredentialStore(store)
	a.SetDirectoryStore(store)
	a.SetLocalEnabled(true)
	seedUser(t, store, "ops@example.com", "owner-password-1", true)
	seedUser(t, store, "op\u017f@example.com", "alias-password-1", true)

	alias := newClient(t, a)
	alias.login("op\u017f@example.com", "alias-password-1")
	if w := alias.do("GET", "/auth/admin/users", nil); w.Code == http.StatusOK {
		t.Fatal("a case-fold alias of OWNER_EMAIL must not be the owner")
	}
	real := newClient(t, a)
	real.login("ops@example.com", "owner-password-1")
	if w := real.do("GET", "/auth/admin/users", nil); w.Code != http.StatusOK {
		t.Fatalf("the owner = %d", w.Code)
	}
}

// The global SCIM mount only re-points emails of accounts SCIM provisioned; a deprovisioning PUT
// changes nothing else.
func TestGlobalSCIMKeepsOtherAccountsEmails(t *testing.T) {
	a, s, _ := newTestAuth(t)
	owner := seedUser(t, s, "owner@example.com", "owner-password-1", true)
	raw := "axk_scim_only"
	h := sha256.Sum256([]byte(raw))
	if _, err := s.CreateAPIKey("idp", nil, []string{"scim"}, raw[:8], h[:], nil); err != nil {
		t.Fatal(err)
	}
	srv := scim.NewServer(s, func(tok string) bool { return a.ValidateAPIKeyScope(tok, "scim") }).Handler()

	if w := scimDo(t, srv, raw, "PUT", "/Users/"+owner.ID, `{"userName":"attacker@evil.test"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("re-pointing a local account's email = %d, want 400", w.Code)
	}
	if u, _ := s.UserByID(owner.ID); u.Email != "owner@example.com" {
		t.Fatalf("email changed to %q", u.Email)
	}
	w := scimDo(t, srv, raw, "POST", "/Users", `{"userName":"dev@corp.com"}`)
	id := decode(t, w)["id"].(string)
	if w := scimDo(t, srv, raw, "PUT", "/Users/"+id, `{"userName":"dev2@corp.com"}`); w.Code != http.StatusOK {
		t.Fatalf("re-pointing a SCIM account's email = %d", w.Code)
	}
	if w := scimDo(t, srv, raw, "PUT", "/Users/"+id, `{"userName":"dev3@corp.com","active":false}`); w.Code != http.StatusOK {
		t.Fatalf("deprovisioning PUT = %d", w.Code)
	}
	if u, _ := s.UserByID(id); !u.Disabled || u.Email != "dev2@corp.com" {
		t.Fatalf("a deprovisioning PUT must only deprovision: %+v", u)
	}
}

// ValidateAPIKey refuses org-bound keys (a customer's key never passes a global surface), and the
// global SCIM wiring the README shows refuses them and scope-less keys.
func TestOrgBoundAndScopelessKeysOffGlobalSurfaces(t *testing.T) {
	a, s, _ := newOrgAuth(t)
	org := seedOrg(t, s, "acme", nil)
	orgKey := orgScimKey(t, s, org.ID, "scim-acme")
	if _, ok := a.ValidateAPIKey(orgKey); ok {
		t.Fatal("ValidateAPIKey must refuse an org-bound key")
	}
	if !a.ValidateOrgAPIKeyScope(orgKey, "scim", org.ID) {
		t.Fatal("the org-bound key must still work for its own org")
	}
	none := "axk_no_scopes"
	h := sha256.Sum256([]byte(none))
	_, _ = s.CreateAPIKey("none", nil, nil, none[:8], h[:], nil)
	global := scim.NewServer(s, func(tok string) bool { return a.ValidateAPIKeyScope(tok, "scim") }).Handler()
	for _, key := range []string{orgKey, none} {
		if w := scimDo(t, global, key, "GET", "/Users", ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("key %q on the global SCIM mount = %d, want 401", key, w.Code)
		}
	}
}

// A reset link mailed to an address the account has since left no longer resets it.
func TestResetLinkRefusedAfterEmailChange(t *testing.T) {
	a, s, m := newTestAuth(t)
	u := seedUser(t, s, "old@x.com", "victim-password-1", true)
	newClient(t, a).do("POST", "/auth/password/reset/request", map[string]any{"email": "old@x.com"})
	tok := tokenRe.FindStringSubmatch(m.waitFor(t, "/reset?token=").text)[1]
	if err := s.SetEmail(u.ID, "new@x.com"); err != nil {
		t.Fatal(err)
	}
	if w := newClient(t, a).do("POST", "/auth/password/reset/confirm", map[string]any{"token": tok, "password": "attacker-password-1"}); w.Code == http.StatusOK {
		t.Fatal("a reset link for the old address must be refused")
	}
}
