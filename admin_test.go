package authx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeDir satisfies DirectoryStore via an embedded nil interface; only the API-key methods the
// access path touches are implemented.
type fakeDir struct {
	DirectoryStore
	hash string
	info APIKeyInfo
}

func (f *fakeDir) APIKeyByHash(hash []byte) (*APIKeyInfo, error) {
	if string(hash) == f.hash {
		cp := f.info
		return &cp, nil
	}
	return nil, ErrNoCredential
}
func (f *fakeDir) TouchAPIKey(uint) error { return nil }

func TestAdminGuardScopesAndGroups(t *testing.T) {
	raw, prefix, hash := generateAPIKey()
	a := &Authenticator{cfg: Config{SessionSecret: []byte("0123456789abcdef0123456789abcdef"), OwnerEmail: "owner@x.com"}}
	a.dir = &fakeDir{hash: string(hash), info: APIKeyInfo{ID: 1, Prefix: prefix, Groups: []string{"team"}, Scopes: []string{"admin"}}}

	bearer := func(key string) *reqCtx {
		req := httptest.NewRequest(http.MethodGet, "/auth/admin/groups", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		return a.newCtx(httptest.NewRecorder(), req)
	}

	// adminGuard accepts an admin-scoped key, rejects an invalid one.
	if !a.adminGuard(bearer(raw)) {
		t.Fatal("adminGuard should accept an admin-scoped key")
	}
	if c := bearer("axk_nope"); a.adminGuard(c) {
		t.Fatal("adminGuard should reject an invalid key")
	}

	// Scope checks (deny-by-default).
	if !a.ValidateAPIKeyScope(raw, "admin") || a.ValidateAPIKeyScope(raw, "scim") {
		t.Fatal("key should have 'admin' scope but not 'scim'")
	}
	if KeyHasScope(&APIKeyInfo{}, "anything") {
		t.Fatal("empty Scopes must grant nothing (deny-by-default)")
	}
	if !KeyHasScope(&APIKeyInfo{Scopes: []string{"*"}}, "anything") {
		t.Fatal(`["*"] must grant everything`)
	}

	// requestGroups merges the key's groups.
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if g := a.requestGroups(req); len(g) == 0 || g[0] != "team" {
		t.Fatalf("requestGroups: %v", g)
	}

	// RequireGroupsHTTP allows a member, forbids a non-member (no session, key not in group "x").
	deny := httptest.NewRecorder()
	a.RequireGroupsHTTP("x")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(deny, req)
	if deny.Code != http.StatusForbidden {
		t.Fatalf("RequireGroupsHTTP should forbid a non-member: got %d", deny.Code)
	}
}
