package authx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// fakeDir satisfies DirectoryStore via an embedded nil interface; only the methods the access /
// API-key path touches are implemented (the rest would panic, and aren't called here).
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

func TestAPIKeyAuthAndGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw, prefix, hash := generateAPIKey()
	a := &Authenticator{cfg: Config{SessionSecret: []byte("0123456789abcdef0123456789abcdef"), OwnerEmail: "owner@x.com"}}
	a.localEnabled = true
	a.dir = &fakeDir{hash: string(hash), info: APIKeyInfo{ID: 1, Name: "ci", Prefix: prefix, Groups: []string{"admin"}}}

	// APIKeyAuth stamps the key's groups + the admin guard accepts a valid key.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/auth/admin/groups", nil)
	c.Request.Header.Set("Authorization", "Bearer "+raw)
	a.APIKeyAuth()(c)
	v, ok := c.Get(ctxAPIKey)
	info, isInfo := v.(*APIKeyInfo)
	if !ok || !isInfo || len(info.Groups) == 0 || info.Groups[0] != "admin" {
		t.Fatalf("APIKeyAuth did not stamp the key info: ok=%v v=%v", ok, v)
	}
	if !a.adminGuard(c) {
		t.Fatal("adminGuard should accept a valid API key (empty scopes = unrestricted)")
	}

	// An invalid key is rejected (401).
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodPost, "/auth/admin/groups", nil)
	c2.Request.Header.Set("Authorization", "Bearer axk_wrong")
	a.APIKeyAuth()(c2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("invalid key: want 401, got %d", w2.Code)
	}

	// RequireGroups: a session in the group passes; a session without it is forbidden.
	pass := httptest.NewRecorder()
	cp, _ := gin.CreateTestContext(pass)
	cp.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	cp.Set(ctxSessionKey, &SessionClaims{Email: "u@x.com", Groups: []string{"admin"}})
	a.RequireGroups("admin")(cp)
	if pass.Code == http.StatusForbidden {
		t.Fatal("RequireGroups wrongly forbade a member")
	}

	deny := httptest.NewRecorder()
	cd, _ := gin.CreateTestContext(deny)
	cd.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	cd.Set(ctxSessionKey, &SessionClaims{Email: "u@x.com", Groups: []string{"other"}})
	a.RequireGroups("admin")(cd)
	if deny.Code != http.StatusForbidden {
		t.Fatalf("RequireGroups should forbid a non-member: got %d", deny.Code)
	}
}
