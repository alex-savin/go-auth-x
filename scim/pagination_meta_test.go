package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alex-savin/go-auth-x/store/memory"
)

// testServer builds a SCIM server over an in-memory directory with a fixed bearer token.
func testServer(t *testing.T) func(method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	dir := memory.New()
	srv := NewServer(dir, func(tok string) bool { return tok == "secret" })
	h := http.StripPrefix("/scim/v2", srv.Handler())
	return func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	return m
}

func TestSCIMCreateUniqueness(t *testing.T) {
	// A SCIM CREATE onto an existing email must be 409 uniqueness — not a silent login-upsert rebind/reclaim.
	srv := testServer(t)
	body := `{"userName":"u1","emails":[{"value":"dup@x.com","primary":true}]}`
	if w := srv("POST", "/scim/v2/Users", body); w.Code != http.StatusCreated {
		t.Fatalf("first create: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	// Same email via a DIFFERENT userName must conflict rather than rebind the existing user.
	dup := `{"userName":"u2","emails":[{"value":"dup@x.com","primary":true}]}`
	w := srv("POST", "/scim/v2/Users", dup)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate-email create: want 409, got %d (%s)", w.Code, w.Body.String())
	}
	if m := decode(t, w); m["scimType"] != "uniqueness" {
		t.Fatalf("want scimType=uniqueness, got %v", m["scimType"])
	}
}

func TestSCIMPagination(t *testing.T) {
	do := testServer(t)
	for _, u := range []string{"a", "b", "c", "d", "e"} {
		body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + u + `@x.com","active":true}`
		if w := do(http.MethodPost, "/scim/v2/Users", body); w.Code != http.StatusCreated {
			t.Fatalf("seed %s: %d %s", u, w.Code, w.Body.String())
		}
	}

	// First page of 2 (sorted for determinism).
	w := do(http.MethodGet, "/scim/v2/Users?sortBy=userName&count=2", "")
	m := decode(t, w)
	if got := m["totalResults"].(float64); got != 5 {
		t.Fatalf("totalResults: want 5, got %v", got)
	}
	if got := m["itemsPerPage"].(float64); got != 2 {
		t.Fatalf("itemsPerPage: want 2, got %v", got)
	}
	if got := m["startIndex"].(float64); got != 1 {
		t.Fatalf("startIndex: want 1, got %v", got)
	}
	res := m["Resources"].([]any)
	if len(res) != 2 {
		t.Fatalf("page len: want 2, got %d", len(res))
	}
	if un := res[0].(map[string]any)["userName"]; un != "a@x.com" {
		t.Fatalf("first item: want a@x.com, got %v", un)
	}

	// Middle page via startIndex (1-based).
	w = do(http.MethodGet, "/scim/v2/Users?sortBy=userName&startIndex=3&count=2", "")
	m = decode(t, w)
	if got := m["startIndex"].(float64); got != 3 {
		t.Fatalf("startIndex: want 3, got %v", got)
	}
	res = m["Resources"].([]any)
	if len(res) != 2 || res[0].(map[string]any)["userName"] != "c@x.com" {
		t.Fatalf("middle page wrong: %s", w.Body.String())
	}

	// count=0 is a valid "how many?" query: totalResults set, empty page.
	w = do(http.MethodGet, "/scim/v2/Users?count=0", "")
	m = decode(t, w)
	if m["totalResults"].(float64) != 5 || m["itemsPerPage"].(float64) != 0 {
		t.Fatalf("count=0: want total 5 / items 0, got %s", w.Body.String())
	}
	if res := m["Resources"].([]any); len(res) != 0 {
		t.Fatalf("count=0: want empty page, got %d", len(res))
	}

	// startIndex past the end → empty page, but totalResults still full.
	w = do(http.MethodGet, "/scim/v2/Users?startIndex=99", "")
	m = decode(t, w)
	if m["totalResults"].(float64) != 5 || m["itemsPerPage"].(float64) != 0 {
		t.Fatalf("startIndex past end: %s", w.Body.String())
	}
}

func TestSCIMMetaTimestamps(t *testing.T) {
	do := testServer(t)
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"m@x.com","active":true}`
	w := do(http.MethodPost, "/scim/v2/Users", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	meta := decode(t, w)["meta"].(map[string]any)
	created, _ := meta["created"].(string)
	modified, _ := meta["lastModified"].(string)
	if created == "" {
		t.Fatalf("meta.created missing: %s", w.Body.String())
	}
	if modified == "" {
		t.Fatalf("meta.lastModified missing: %s", w.Body.String())
	}
	// created and lastModified should be RFC3339 and equal for a never-updated resource.
	if created != modified {
		t.Fatalf("created (%s) != lastModified (%s) for a fresh user", created, modified)
	}
}

func TestSCIMSchemas(t *testing.T) {
	do := testServer(t)

	// /Schemas is a ListResponse of full documents.
	w := do(http.MethodGet, "/scim/v2/Schemas", "")
	m := decode(t, w)
	if m["totalResults"].(float64) != 2 {
		t.Fatalf("schemas total: want 2, got %v", m["totalResults"])
	}
	docs := m["Resources"].([]any)
	foundUserAttrs := false
	for _, d := range docs {
		doc := d.(map[string]any)
		if doc["id"] == schemaUser {
			attrs, ok := doc["attributes"].([]any)
			if !ok || len(attrs) == 0 {
				t.Fatalf("User schema has no attributes: %v", doc)
			}
			foundUserAttrs = true
		}
	}
	if !foundUserAttrs {
		t.Fatalf("User schema document not found in /Schemas")
	}

	// /Schemas/{id} returns the single document.
	w = do(http.MethodGet, "/scim/v2/Schemas/"+schemaGroup, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /Schemas/{group}: %d", w.Code)
	}
	if decode(t, w)["id"] != schemaGroup {
		t.Fatalf("wrong schema returned: %s", w.Body.String())
	}

	// Unknown schema → 404.
	if w := do(http.MethodGet, "/scim/v2/Schemas/urn:nope", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown schema: want 404, got %d", w.Code)
	}
}
