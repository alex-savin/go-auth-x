package scim

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/store/memory"
)

// flakyDir hides the store's BatchGroupStore (forcing the per-member fallback) and fails
// AddUserToGroup for one user.
type flakyDir struct {
	authx.DirectoryStore
	failFor string
}

func (d flakyDir) AddUserToGroup(userID, groupID string) error {
	if userID == d.failFor {
		return errors.New("store unavailable")
	}
	return d.DirectoryStore.AddUserToGroup(userID, groupID)
}

// countingDir records which membership-add path the server took.
type countingDir struct {
	*memory.Store
	single, batch int
}

func (d *countingDir) AddUserToGroup(userID, groupID string) error {
	d.single++
	return d.Store.AddUserToGroup(userID, groupID)
}

func (d *countingDir) AddUsersToGroup(userIDs []string, groupID string) error {
	d.batch++
	return d.Store.AddUsersToGroup(userIDs, groupID)
}

func membersBody(ids ...string) string {
	vals := make([]string, len(ids))
	for i, id := range ids {
		vals[i] = `{"value":"` + id + `"}`
	}
	return "[" + strings.Join(vals, ",") + "]"
}

func newMembershipServer(dir authx.DirectoryStore, logs *bytes.Buffer) func(method, path, body string) *httptest.ResponseRecorder {
	srv := NewServer(dir, func(tok string) bool { return tok == "secret" })
	srv.SetLogger(slog.New(slog.NewTextHandler(logs, nil)))
	h := http.StripPrefix("/scim/v2", srv.Handler())
	return func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
}

// TestGroupMembership_FallbackIsBestEffort is the regression for a group sync over a store without
// BatchGroupStore: one failing member must not drop the members after it, and the failure is logged.
func TestGroupMembership_FallbackIsBestEffort(t *testing.T) {
	mem := memory.New()
	u1, _ := mem.CreateLocalUser("u1@x.com", "U1")
	u2, _ := mem.CreateLocalUser("u2@x.com", "U2")
	u3, _ := mem.CreateLocalUser("u3@x.com", "U3")
	var logs bytes.Buffer
	do := newMembershipServer(flakyDir{DirectoryStore: mem, failFor: u1.ID}, &logs)
	assertMembers := func(group string, want ...string) {
		t.Helper()
		g, err := mem.GroupByName(group)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := mem.GroupMembers(g.ID)
		ids := map[string]bool{}
		for _, u := range got {
			ids[u.ID] = true
		}
		if len(ids) != len(want) {
			t.Fatalf("%s: want members %v, got %v", group, want, ids)
		}
		for _, id := range want {
			if !ids[id] {
				t.Fatalf("%s: want members %v, got %v", group, want, ids)
			}
		}
	}

	// Create with members — the failing one is listed first.
	if w := do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"eng","members":`+membersBody(u1.ID, u2.ID, u3.ID)+`}`); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	assertMembers("eng", u2.ID, u3.ID)

	// PATCH add — the common IdP incremental push.
	w := do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"ops"}`)
	ops, _ := mem.GroupByName("ops")
	patch := `{"Operations":[{"op":"add","path":"members","value":` + membersBody(u1.ID, u2.ID) + `}]}`
	if w = do(http.MethodPatch, "/scim/v2/Groups/"+ops.ID, patch); w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	assertMembers("ops", u2.ID)

	if !strings.Contains(logs.String(), "group membership add incomplete") || !strings.Contains(logs.String(), "store unavailable") {
		t.Fatalf("an incomplete membership write must be logged, got %q", logs.String())
	}
}

// TestGroupMembership_UsesBatchStore pins that a BatchGroupStore gets ONE call per membership change
// instead of one per member (the N+1 on large group syncs).
func TestGroupMembership_UsesBatchStore(t *testing.T) {
	dir := &countingDir{Store: memory.New()}
	var ids []string
	for _, e := range []string{"a@x.com", "b@x.com", "c@x.com"} {
		u, _ := dir.CreateLocalUser(e, "")
		ids = append(ids, u.ID)
	}
	var logs bytes.Buffer
	do := newMembershipServer(dir, &logs)

	if w := do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"eng","members":`+membersBody(ids...)+`}`); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	g, _ := dir.GroupByName("eng")
	if w := do(http.MethodPut, "/scim/v2/Groups/"+g.ID, `{"displayName":"eng","members":`+membersBody(ids[:2]...)+`}`); w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if dir.batch != 2 || dir.single != 0 {
		t.Fatalf("want 2 batch adds and no per-member adds, got batch=%d single=%d", dir.batch, dir.single)
	}
	if m, _ := dir.GroupMembers(g.ID); len(m) != 2 {
		t.Fatalf("PUT must leave exactly the 2 listed members, got %d", len(m))
	}
	if logs.Len() != 0 {
		t.Fatalf("a clean sync must log nothing, got %q", logs.String())
	}
}
