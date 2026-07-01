package authx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// scopeFakeDir is a minimal DirectoryStore that resolves exactly one API key by hash, returning a
// COPY of info (so callers can't mutate stored state). Mirrors the fakeDir pattern in admin_test.go
// but is named distinctly to avoid collisions.
type scopeFakeDir struct {
	DirectoryStore
	hash string
	info APIKeyInfo
}

func (f *scopeFakeDir) APIKeyByHash(hash []byte) (*APIKeyInfo, error) {
	if string(hash) == f.hash {
		cp := f.info
		return &cp, nil
	}
	return nil, ErrNoCredential
}
func (f *scopeFakeDir) TouchAPIKey(uint) error { return nil }

// TestScopeDenyByDefaultUnit nails the pure KeyHasScope contract under adversarial inputs.
func TestScopeDenyByDefaultUnit(t *testing.T) {
	// (1) empty grants nothing.
	if KeyHasScope(&APIKeyInfo{}, "anything") {
		t.Fatal("empty Scopes must grant nothing (deny-by-default)")
	}
	if KeyHasScope(&APIKeyInfo{Scopes: []string{}}, "admin") {
		t.Fatal("explicitly empty Scopes slice must grant nothing")
	}
	if KeyHasScope(&APIKeyInfo{Scopes: nil}, "admin") {
		t.Fatal("nil Scopes must grant nothing")
	}

	// (2) "*" grants everything, including arbitrary/unknown scopes.
	for _, s := range []string{"anything", "admin", "scim", "", "*"} {
		if !KeyHasScope(&APIKeyInfo{Scopes: []string{"*"}}, s) {
			t.Fatalf(`["*"] must grant %q`, s)
		}
	}

	// (3) ["scim"] grants "scim" but NOT "admin".
	scim := &APIKeyInfo{Scopes: []string{"scim"}}
	if !KeyHasScope(scim, "scim") {
		t.Fatal(`["scim"] must grant "scim"`)
	}
	if KeyHasScope(scim, "admin") {
		t.Fatal(`["scim"] must NOT grant "admin"`)
	}

	// Adversarial near-misses: no substring/prefix/case leniency, no nil-deref.
	if KeyHasScope(nil, "admin") {
		t.Fatal("nil info must deny")
	}
	if KeyHasScope(&APIKeyInfo{Scopes: []string{"admin"}}, "Admin") {
		t.Fatal("scope match must be case-sensitive; 'admin' must not grant 'Admin'")
	}
	if KeyHasScope(&APIKeyInfo{Scopes: []string{"admin"}}, "ad") {
		t.Fatal("scope match must be exact; 'admin' must not grant prefix 'ad'")
	}
	if KeyHasScope(&APIKeyInfo{Scopes: []string{"adminx"}}, "admin") {
		t.Fatal("scope match must be exact; 'adminx' must not grant 'admin'")
	}
	if KeyHasScope(&APIKeyInfo{Scopes: []string{"scim", "reports"}}, "admin") {
		t.Fatal("a key without 'admin' must not gain it from unrelated scopes")
	}
}

// TestScopelessKeyCannotActAsAdmin is the integration claim: a real (generateAPIKey-minted) key with
// an EMPTY scopes list must be rejected by ValidateAPIKeyScope("admin") AND must fail adminGuard,
// while a ["*"] key passes both. Breaking either direction is a privilege-escalation defect.
func TestScopelessKeyCannotActAsAdmin(t *testing.T) {
	bearerCtx := func(a *Authenticator, key string) *reqCtx {
		req := httptest.NewRequest(http.MethodGet, "/auth/admin/groups", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		return a.newCtx(httptest.NewRecorder(), req)
	}
	newAuth := func(info APIKeyInfo, hash []byte) *Authenticator {
		a := &Authenticator{cfg: Config{
			SessionSecret: []byte("0123456789abcdef0123456789abcdef"),
			OwnerEmail:    "owner@x.com",
		}}
		a.dir = &scopeFakeDir{hash: string(hash), info: info}
		return a
	}

	// --- Scopeless key: VALID key material, but zero scopes. Must NOT be admin anywhere. ---
	rawEmpty, prefixEmpty, hashEmpty := generateAPIKey()
	aEmpty := newAuth(APIKeyInfo{ID: 1, Prefix: prefixEmpty, Groups: []string{"team"}, Scopes: nil}, hashEmpty)

	// Sanity: the key itself is valid (resolves), proving the denial is about SCOPE, not bad material.
	if _, ok := aEmpty.ValidateAPIKey(rawEmpty); !ok {
		t.Fatal("precondition: scopeless key should still be a VALID (resolvable) key")
	}
	if aEmpty.ValidateAPIKeyScope(rawEmpty, "admin") {
		t.Fatal("DEFECT: scopeless key passed ValidateAPIKeyScope('admin')")
	}
	if aEmpty.ValidateAPIKeyScope(rawEmpty, "scim") {
		t.Fatal("DEFECT: scopeless key passed ValidateAPIKeyScope('scim')")
	}
	if aEmpty.ValidateAPIKeyScope(rawEmpty, "*") {
		t.Fatal("DEFECT: scopeless key passed ValidateAPIKeyScope('*')")
	}
	if aEmpty.adminGuard(bearerCtx(aEmpty, rawEmpty)) {
		t.Fatal("DEFECT: scopeless key passed adminGuard — privilege escalation")
	}

	// Also assert explicit-empty-slice (not just nil) is denied through the full integration path.
	rawEmpty2, prefix2, hash2 := generateAPIKey()
	aEmpty2 := newAuth(APIKeyInfo{ID: 2, Prefix: prefix2, Scopes: []string{}}, hash2)
	if aEmpty2.ValidateAPIKeyScope(rawEmpty2, "admin") || aEmpty2.adminGuard(bearerCtx(aEmpty2, rawEmpty2)) {
		t.Fatal("DEFECT: empty-slice-scoped key acted as admin")
	}

	// --- A key scoped ONLY to ["scim"] must not reach admin either. ---
	rawScim, prefixScim, hashScim := generateAPIKey()
	aScim := newAuth(APIKeyInfo{ID: 3, Prefix: prefixScim, Scopes: []string{"scim"}}, hashScim)
	if !aScim.ValidateAPIKeyScope(rawScim, "scim") {
		t.Fatal("scim-scoped key should pass ValidateAPIKeyScope('scim')")
	}
	if aScim.ValidateAPIKeyScope(rawScim, "admin") {
		t.Fatal("DEFECT: scim-scoped key passed ValidateAPIKeyScope('admin')")
	}
	if aScim.adminGuard(bearerCtx(aScim, rawScim)) {
		t.Fatal("DEFECT: scim-scoped key passed adminGuard")
	}

	// --- Positive control: ["*"] root key passes ValidateAPIKeyScope('admin') AND adminGuard. ---
	rawStar, prefixStar, hashStar := generateAPIKey()
	aStar := newAuth(APIKeyInfo{ID: 4, Prefix: prefixStar, Scopes: []string{"*"}}, hashStar)
	if !aStar.ValidateAPIKeyScope(rawStar, "admin") {
		t.Fatal("['*'] key should pass ValidateAPIKeyScope('admin')")
	}
	if !aStar.adminGuard(bearerCtx(aStar, rawStar)) {
		t.Fatal("['*'] key should pass adminGuard")
	}

	// Cross-check: a scopeless key must NOT be acceptable just because some OTHER key is ["*"].
	// (Reuse aEmpty: presenting the scopeless raw against the star-configured authenticator fails
	// because the hash won't resolve — confirms no global bypass.)
	if aStar.adminGuard(bearerCtx(aStar, rawEmpty)) {
		t.Fatal("DEFECT: a foreign/unknown key was accepted by adminGuard")
	}
}
