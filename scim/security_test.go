package scim

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// Regression tests for the 2026-11 security audit: /Bulk nesting (H1) and malformed operations (L10).
func TestBulkRefusesNestingAndMalformedOps(t *testing.T) {
	dir := memory.New()
	h := NewServer(dir, func(tok string) bool { return tok == "secret" }).Handler()
	do := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/Bulk", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	// However the path is spelled, a bulk operation can't be a bulk request.
	for i, p := range []string{"/Bulk", "/Bulk?", "/%42ulk", "/bulk/", "http://h/Bulk", "//h/Bulk"} {
		body := fmt.Sprintf(`{"Operations":[{"method":"POST","path":%q,"data":{"Operations":[`+
			`{"method":"POST","path":"/Users","data":{"userName":"smuggled%d@x.com"}}]}}]}`, p, i)
		if w := do(body); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"400"`) {
			t.Fatalf("nested bulk via %q = %d %s", p, w.Code, w.Body.String())
		}
		if _, err := dir.UserByEmail(fmt.Sprintf("smuggled%d@x.com", i)); err == nil {
			t.Fatalf("nested bulk via %q ran its operation", p)
		}
	}
	// A malformed path or method is that operation's 400, and the others still run.
	w := do(`{"Operations":[{"method":"POST","path":"Users","data":{"userName":"a@x.com"}},` +
		`{"method":"GET /x","path":"/Users"},{"method":"POST","path":"/Users","data":{"userName":"ok@x.com"}}]}`)
	if w.Code != http.StatusOK || strings.Count(w.Body.String(), `"status":"400"`) != 2 {
		t.Fatalf("malformed ops = %d %s", w.Code, w.Body.String())
	}
	if _, err := dir.UserByEmail("ok@x.com"); err != nil {
		t.Fatal("the valid operation must still run")
	}
}

// failingDir is a directory whose deactivations, re-reads or member removals can be made to fail.
type failingDir struct {
	authx.DirectoryStore
	failDisable, failRead, failRemove bool
}

var errDown = errors.New("store unavailable")

func (f *failingDir) SetUserDisabled(id string, disabled bool) error {
	if f.failDisable {
		return errDown
	}
	return f.DirectoryStore.SetUserDisabled(id, disabled)
}

func (f *failingDir) UserByID(id string) (*authx.AuthUser, error) {
	if f.failRead {
		return nil, errDown
	}
	return f.DirectoryStore.UserByID(id)
}

func (f *failingDir) RemoveUserFromGroup(userID, groupID string) error {
	if f.failRemove {
		return errDown
	}
	return f.DirectoryStore.RemoveUserFromGroup(userID, groupID)
}

func scimServer(dir authx.DirectoryStore) func(method, path, body string) *httptest.ResponseRecorder {
	h := NewServer(dir, func(tok string) bool { return tok == "secret" }).Handler()
	return func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
}

const deactivate = `{"Operations":[{"op":"replace","path":"active","value":false}]}`

// A deprovision that didn't happen isn't acknowledged. The IdP takes a 200 as done and never retries,
// and the leaver keeps a working account: PATCH (what Entra and Okta send) and a create with
// active=false answered 200/201 when the store write failed.
func TestFailedDeprovisionIsNotAcknowledged(t *testing.T) {
	mem := memory.New()
	dir := &failingDir{DirectoryStore: mem}
	do := scimServer(dir)
	u, _ := mem.UpsertExternalUser("scim:leaver", "leaver@x.com", "Leaver", true)

	dir.failDisable = true
	if w := do("PATCH", "/Users/"+u.ID, deactivate); w.Code < 500 {
		t.Fatalf("PATCH active=false with a failing store = %d %s", w.Code, w.Body.String())
	}
	if w := do("POST", "/Users", `{"userName":"new@x.com","active":false}`); w.Code < 500 {
		t.Fatalf("POST active=false with a failing store = %d %s", w.Code, w.Body.String())
	}
	if got, _ := mem.UserByID(u.ID); got.Disabled {
		t.Fatal("precondition: the write failed")
	}
	dir.failDisable = false

	// The write went through but the re-read failed: an error, not a made-up resource.
	dir.failRead = true
	h := NewServer(&readFailsAfterFirst{failingDir: dir}, func(tok string) bool { return tok == "secret" }).Handler()
	r := httptest.NewRequest("PATCH", "/Users/"+u.ID, strings.NewReader(deactivate))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code < 500 {
		t.Fatalf("PATCH whose re-read fails = %d %s", w.Code, w.Body.String())
	}
}

// readFailsAfterFirst lets the first UserByID through (the handler's lookup) and fails the next.
type readFailsAfterFirst struct {
	*failingDir
	reads int
}

func (r *readFailsAfterFirst) UserByID(id string) (*authx.AuthUser, error) {
	r.reads++
	if r.reads == 1 {
		return r.failingDir.DirectoryStore.UserByID(id)
	}
	return nil, errDown
}

// Whether an account may sign in is SCIM's to say only for accounts it provisioned. A scim-scoped
// key could disable the owner's local account, and a replace that left `active` out re-enabled an
// account an operator had disabled.
func TestSCIMActivatesOnlyAccountsItProvisioned(t *testing.T) {
	mem := memory.New()
	do := scimServer(mem)
	local, _ := mem.CreateLocalUser("owner@example.com", "Owner")
	_ = mem.SetEmailVerified(local.ID, true)
	for _, call := range [][3]string{
		{"DELETE", "/Users/" + local.ID, ""},
		{"PATCH", "/Users/" + local.ID, deactivate},
		{"PUT", "/Users/" + local.ID, `{"userName":"owner@example.com","active":false}`},
	} {
		if w := do(call[0], call[1], call[2]); w.Code != http.StatusBadRequest {
			t.Fatalf("%s on a local account = %d %s, want 400", call[0], w.Code, w.Body.String())
		}
	}
	if got, _ := mem.UserByID(local.ID); got.Disabled {
		t.Fatal("SCIM disabled an account it didn't provision")
	}
	// An operator's disable isn't undone by a replace, with or without `active`.
	_ = mem.SetUserDisabled(local.ID, true)
	if w := do("PUT", "/Users/"+local.ID, `{"userName":"owner@example.com","name":{"formatted":"Renamed"}}`); w.Code != http.StatusOK {
		t.Fatalf("a profile replace of a local account = %d %s", w.Code, w.Body.String())
	}
	if w := do("PUT", "/Users/"+local.ID, `{"userName":"owner@example.com","active":true}`); w.Code != http.StatusBadRequest {
		t.Fatalf("re-enabling a local account = %d, want 400", w.Code)
	}
	if got, _ := mem.UserByID(local.ID); !got.Disabled || got.Name != "Renamed" {
		t.Fatalf("the replace should rename and leave the account disabled: %+v", got)
	}

	// Its own accounts it activates and deactivates as before; a replace without `active` leaves them.
	w := do("POST", "/Users", `{"userName":"dev@corp.com"}`)
	id := decode(t, w)["id"].(string)
	if w := do("PATCH", "/Users/"+id, deactivate); w.Code != http.StatusOK {
		t.Fatalf("deactivating a provisioned account = %d", w.Code)
	}
	if w := do("PUT", "/Users/"+id, `{"userName":"dev@corp.com"}`); w.Code != http.StatusOK {
		t.Fatalf("replace = %d", w.Code)
	}
	if got, _ := mem.UserByID(id); !got.Disabled {
		t.Fatal("a replace that doesn't mention active re-enabled the account")
	}
	if w := do("PUT", "/Users/"+id, `{"userName":"dev@corp.com","active":true}`); w.Code != http.StatusOK {
		t.Fatalf("reactivating replace = %d", w.Code)
	}
	if got, _ := mem.UserByID(id); got.Disabled {
		t.Fatal("an explicit active=true must reactivate a provisioned account")
	}
}

// A create is a create: a userName that already has an account is a conflict, even when its email
// has changed since — the upsert would re-point the existing account, past If-Match.
func TestCreateWithAnExistingUserNameIsAConflict(t *testing.T) {
	mem := memory.New()
	do := scimServer(mem)
	w := do("POST", "/Users", `{"userName":"jdoe","emails":[{"value":"jdoe@corp.com"}]}`)
	id := decode(t, w)["id"].(string)
	if w := do("POST", "/Users", `{"userName":"jdoe","emails":[{"value":"elsewhere@evil.test"}]}`); w.Code != http.StatusConflict {
		t.Fatalf("a second create for the userName = %d %s, want 409", w.Code, w.Body.String())
	}
	if u, _ := mem.UserByID(id); u.Email != "jdoe@corp.com" {
		t.Fatalf("the create re-pointed the account to %q", u.Email)
	}
}

// A group PATCH this server can't apply is refused, not answered 200, and a member filter is read
// exactly: `members[value ne "1"]` removed user 1 (the first quoted string was taken as the id).
func TestGroupPatchAppliesExactlyWhatItUnderstands(t *testing.T) {
	mem := memory.New()
	do := scimServer(mem)
	var ids []string
	for _, n := range []string{"a@x.com", "b@x.com"} {
		ids = append(ids, decode(t, do("POST", "/Users", `{"userName":"`+n+`"}`))["id"].(string))
	}
	g := decode(t, do("POST", "/Groups", `{"displayName":"eng","members":[{"value":"`+ids[0]+`"},{"value":"`+ids[1]+`"}]}`))["id"].(string)
	members := func() int {
		ms, _ := mem.GroupMembers(g)
		return len(ms)
	}
	for _, path := range []string{
		`members[value ne \"` + ids[0] + `\"]`,
		`members[type eq \"User\" and value eq \"` + ids[0] + `\"]`,
		`members[display eq \"a@x.com\"]`,
	} {
		w := do("PATCH", "/Groups/"+g, `{"Operations":[{"op":"remove","path":"`+path+`"}]}`)
		if w.Code != http.StatusBadRequest || members() != 2 {
			t.Fatalf("remove %s = %d with %d members left, want 400 and 2", path, w.Code, members())
		}
	}
	if w := do("PATCH", "/Groups/"+g, `{"Operations":[{"op":"remove","path":"members[value eq \"`+ids[0]+`\"]"}]}`); w.Code != http.StatusOK || members() != 1 {
		t.Fatalf("the supported member removal = %d with %d members", w.Code, members())
	}
	// A replace without a path carries the members in its value.
	if w := do("PATCH", "/Groups/"+g, `{"Operations":[{"op":"replace","value":{"members":[]}}]}`); w.Code != http.StatusOK || members() != 0 {
		t.Fatalf("path-less replace = %d with %d members, want 200 and none", w.Code, members())
	}
}

// A member removal the store failed to make fails the request: answered 200 it is never retried, and
// the user keeps what the group gates.
func TestFailedMemberRemovalIsNotAcknowledged(t *testing.T) {
	mem := memory.New()
	dir := &failingDir{DirectoryStore: mem}
	do := scimServer(dir)
	uid := decode(t, do("POST", "/Users", `{"userName":"a@x.com"}`))["id"].(string)
	g := decode(t, do("POST", "/Groups", `{"displayName":"admins","members":[{"value":"`+uid+`"}]}`))["id"].(string)
	dir.failRemove = true
	for _, call := range [][2]string{
		{"PUT", `{"displayName":"admins","members":[]}`},
		{"PATCH", `{"Operations":[{"op":"remove","path":"members"}]}`},
		{"PATCH", `{"Operations":[{"op":"remove","path":"members[value eq \"` + uid + `\"]"}]}`},
	} {
		if w := do(call[0], "/Groups/"+g, call[1]); w.Code < 500 {
			t.Fatalf("%s %s with a failing store = %d", call[0], call[1], w.Code)
		}
	}
}

// The mount takes a Bearer token, and never hands its validator an empty one.
func TestAuthNeedsANonEmptyBearerToken(t *testing.T) {
	h := NewServer(memory.New(), func(tok string) bool { return tok == "" || tok == "Basic abc" }).Handler() // a validator that would accept them
	for _, auth := range []string{"", "Bearer ", "Bearer    ", "Basic abc"} {
		r := httptest.NewRequest("GET", "/Users", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q = %d, want 401", auth, w.Code)
		}
	}
}
