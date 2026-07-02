package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alex-savin/go-auth-x/store/memory"
)

func newTestServer() (http.Handler, func(method, path, body string) *httptest.ResponseRecorder) {
	dir := memory.New()
	srv := NewServer(dir, func(tok string) bool { return tok == "secret" })
	h := http.StripPrefix("/scim/v2", srv.Handler())
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	return h, do
}

// TestCreateUserActiveDefaultsTrue pins H6: a create payload that OMITS "active" must NOT disable the
// new account (RFC 7644 default is true).
func TestCreateUserActiveDefaultsTrue(t *testing.T) {
	_, do := newTestServer()
	w := do(http.MethodPost, "/scim/v2/Users", `{"userName":"noactive@x.com"}`) // no "active" field
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var u scimUser
	_ = json.Unmarshal(w.Body.Bytes(), &u)
	if !u.Active {
		t.Fatal("a user created without an explicit active field must be active, not disabled")
	}
	// An explicit active:false is still honored.
	w = do(http.MethodPost, "/scim/v2/Users", `{"userName":"off@x.com","active":false}`)
	var off scimUser
	_ = json.Unmarshal(w.Body.Bytes(), &off)
	if off.Active {
		t.Fatal("active:false must disable the created user")
	}
}

// TestCreateGroupDuplicateConflict pins #64: a duplicate displayName is 409 uniqueness.
func TestCreateGroupDuplicateConflict(t *testing.T) {
	_, do := newTestServer()
	if w := do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"eng"}`); w.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", w.Code, w.Body.String())
	}
	w := do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"eng"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "uniqueness") {
		t.Fatalf("duplicate group: want 409 uniqueness, got %d %s", w.Code, w.Body.String())
	}
}

// TestPatchGroupReplaceAndValuePathRemove pins M4: replace sets the whole membership; a valuePath
// remove drops a single member.
func TestPatchGroupReplaceAndValuePathRemove(t *testing.T) {
	_, do := newTestServer()
	for _, e := range []string{"a@x.com", "b@x.com", "c@x.com"} {
		do(http.MethodPost, "/scim/v2/Users", `{"userName":"`+e+`","active":true}`)
	}
	gw := do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"team"}`)
	var g scimGroup
	_ = json.Unmarshal(gw.Body.Bytes(), &g)

	members := func() int {
		w := do(http.MethodGet, "/scim/v2/Groups/"+g.ID, "")
		var got scimGroup
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		return len(got.Members)
	}

	// replace → exactly members {1,2}.
	do(http.MethodPatch, "/scim/v2/Groups/"+g.ID,
		`{"Operations":[{"op":"replace","path":"members","value":[{"value":"1"},{"value":"2"}]}]}`)
	if n := members(); n != 2 {
		t.Fatalf("after replace: want 2 members, got %d", n)
	}
	// replace again with {3} → the earlier members are cleared (not merely added to).
	do(http.MethodPatch, "/scim/v2/Groups/"+g.ID,
		`{"Operations":[{"op":"replace","path":"members","value":[{"value":"3"}]}]}`)
	if n := members(); n != 1 {
		t.Fatalf("replace must clear the old set: want 1 member, got %d", n)
	}
	// valuePath remove of member 3 → empty.
	do(http.MethodPatch, "/scim/v2/Groups/"+g.ID,
		`{"Operations":[{"op":"remove","path":"members[value eq \"3\"]"}]}`)
	if n := members(); n != 0 {
		t.Fatalf("valuePath remove must drop the member: want 0, got %d", n)
	}
}

// TestFilterDepthLimited pins M3: a pathologically nested filter is rejected, not a stack overflow.
func TestFilterDepthLimited(t *testing.T) {
	_, do := newTestServer()
	deep := strings.Repeat("(", 500) + `userName eq "x"` + strings.Repeat(")", 500)
	w := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(deep), "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("deeply nested filter: want 400, got %d", w.Code)
	}
}
