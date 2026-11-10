package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/alex-savin/go-auth-x/store/gormstore"
)

// gormServer is a SCIM server over a fresh gormstore (SQLite). The other tests of this package run on
// the memory store; what depends on the store's own queries is tested here.
func gormServer(t *testing.T) (*gormstore.Store, func(method, path, body string) *httptest.ResponseRecorder) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "scim.db")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	s, err := gormstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	h := NewServer(s, func(tok string) bool { return tok == "secret" }).Handler()
	return s, func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
}

// Removing a member through SCIM removes that member on gormstore too. Its group joins returned the
// membership row's id as the user's, so a PUT or PATCH that dropped a member answered 200 and removed
// nobody (or someone else), and the group reported the wrong member ids to the IdP.
func TestGroupMemberRemovalOnGormstore(t *testing.T) {
	s, do := gormServer(t)
	ids := map[string]string{}
	for _, n := range []string{"a@x.com", "b@x.com", "mallory@x.com"} {
		w := do("POST", "/Users", `{"userName":"`+n+`"}`)
		var u struct{ ID string }
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &u) != nil || u.ID == "" {
			t.Fatalf("create %s = %d %s", n, w.Code, w.Body.String())
		}
		ids[n] = u.ID
	}
	mallory, a := ids["mallory@x.com"], ids["a@x.com"]
	type group struct {
		ID      string
		Members []struct{ Value, Display string }
	}
	inGroup := func() bool {
		gs, err := s.UserGroups(mallory)
		if err != nil {
			t.Fatal(err)
		}
		return len(gs) != 0
	}
	// The first membership row (id 1) is the third user's: the ids differ.
	create := func() group {
		t.Helper()
		w := do("POST", "/Groups", `{"displayName":"admins","members":[{"value":"`+mallory+`"}]}`)
		var g group
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &g) != nil {
			t.Fatalf("create group = %d %s", w.Code, w.Body.String())
		}
		if len(g.Members) != 1 || g.Members[0].Value != mallory {
			t.Fatalf("the group reports members %+v, want user %s", g.Members, mallory)
		}
		return g
	}
	g := create()

	if w := do("PUT", "/Groups/"+g.ID, `{"displayName":"admins","members":[]}`); w.Code != http.StatusOK || inGroup() {
		t.Fatalf("PUT with no members = %d, still a member: %v", w.Code, inGroup())
	}
	add := `{"Operations":[{"op":"add","path":"members","value":[{"value":"` + mallory + `"}]}]}`
	if w := do("PATCH", "/Groups/"+g.ID, add); w.Code != http.StatusOK || !inGroup() {
		t.Fatalf("PATCH add = %d %s", w.Code, w.Body.String())
	}
	if w := do("PATCH", "/Groups/"+g.ID, `{"Operations":[{"op":"remove","path":"members"}]}`); w.Code != http.StatusOK || inGroup() {
		t.Fatalf("PATCH remove members = %d, still a member: %v", w.Code, inGroup())
	}
	if w := do("PATCH", "/Groups/"+g.ID, add); w.Code != http.StatusOK || !inGroup() {
		t.Fatalf("PATCH add = %d %s", w.Code, w.Body.String())
	}
	replace := `{"Operations":[{"op":"replace","path":"members","value":[{"value":"` + a + `"}]}]}`
	w := do("PATCH", "/Groups/"+g.ID, replace)
	if w.Code != http.StatusOK || inGroup() {
		t.Fatalf("PATCH replace = %d, still a member: %v", w.Code, inGroup())
	}
	var got group
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Members) != 1 || got.Members[0].Value != a {
		t.Fatalf("after the replace the group reports %+v, want only user %s", got.Members, a)
	}
}
