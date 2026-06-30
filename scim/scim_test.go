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

func TestSCIMUserLifecycle(t *testing.T) {
	dir := memory.New()
	srv := NewServer(dir, func(tok string) bool { return tok == "secret" })
	h := http.StripPrefix("/scim/v2", srv.Handler()) // mount as a consumer would

	do := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// Unauthorized without a valid bearer token.
	if w := do(http.MethodGet, "/scim/v2/Users", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", w.Code)
	}

	// Provision a user.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a@b.com","active":true,"emails":[{"value":"a@b.com","primary":true}]}`
	w := do(http.MethodPost, "/scim/v2/Users", body, "secret")
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d body=%s", w.Code, w.Body.String())
	}
	var created scimUser
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.ID == "" || created.UserName != "a@b.com" || !created.Active {
		t.Fatalf("created user wrong: %+v", created)
	}

	// List + userName filter finds it.
	filterURL := "/scim/v2/Users?filter=" + url.QueryEscape(`userName eq "a@b.com"`)
	if w := do(http.MethodGet, filterURL, "", "secret"); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "a@b.com") {
		t.Fatalf("list/filter: %d %s", w.Code, w.Body.String())
	}

	// Deprovision via PATCH active=false.
	patch := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
	w = do(http.MethodPatch, "/scim/v2/Users/"+created.ID, patch, "secret")
	if w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	var patched scimUser
	_ = json.Unmarshal(w.Body.Bytes(), &patched)
	if patched.Active {
		t.Fatal("user should be deactivated after PATCH active=false")
	}

	// PUT replaces the user (reactivate + rename).
	put := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a@b.com","active":true,"name":{"formatted":"Renamed"}}`
	w = do(http.MethodPut, "/scim/v2/Users/"+created.ID, put, "secret")
	if w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	var replaced scimUser
	_ = json.Unmarshal(w.Body.Bytes(), &replaced)
	if !replaced.Active {
		t.Fatal("PUT active=true should reactivate the user")
	}
}

func TestSCIMFiltersAndBulk(t *testing.T) {
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

	// Bulk-provision two users in one request.
	bulk := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
		{"method":"POST","path":"/Users","bulkId":"a","data":{"userName":"alice@acme.com","active":true}},
		{"method":"POST","path":"/Users","bulkId":"b","data":{"userName":"bob@acme.com","active":true}}
	]}`
	w := do(http.MethodPost, "/scim/v2/Bulk", bulk)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var br struct {
		Operations []map[string]any `json:"Operations"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &br)
	if len(br.Operations) != 2 {
		t.Fatalf("bulk: want 2 results, got %d", len(br.Operations))
	}
	if br.Operations[0]["status"] != "201" || br.Operations[0]["location"] == nil {
		t.Fatalf("bulk op[0] wrong: %+v", br.Operations[0])
	}
	aliceLoc, _ := br.Operations[0]["location"].(string) // "/Users/<id>"

	// Filter operators (eq / co / sw / pr) over userName+emails (both map to the email).
	for _, c := range []struct {
		filter string
		want   int
	}{
		{`userName sw "alice"`, 1},
		{`emails co "acme"`, 2},
		{`userName eq "bob@acme.com"`, 1},
		{`userName pr`, 2},
		{`userName co "nobody"`, 0},
	} {
		gw := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(c.filter), "")
		var list struct {
			TotalResults int `json:"totalResults"`
		}
		_ = json.Unmarshal(gw.Body.Bytes(), &list)
		if gw.Code != http.StatusOK || list.TotalResults != c.want {
			t.Fatalf("filter %q: want %d, got %d (code %d)", c.filter, c.want, list.TotalResults, gw.Code)
		}
	}

	// Bulk PATCH deactivates alice; `active eq false` then matches exactly one.
	bulkPatch := `{"Operations":[{"method":"PATCH","path":"` + aliceLoc + `","data":{"Operations":[{"op":"replace","path":"active","value":false}]}}]}`
	if pw := do(http.MethodPost, "/scim/v2/Bulk", bulkPatch); pw.Code != http.StatusOK {
		t.Fatalf("bulk patch: %d %s", pw.Code, pw.Body.String())
	}
	iw := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`active eq false`), "")
	var inactive struct {
		TotalResults int `json:"totalResults"`
	}
	_ = json.Unmarshal(iw.Body.Bytes(), &inactive)
	if inactive.TotalResults != 1 {
		t.Fatalf("active eq false: want 1, got %d", inactive.TotalResults)
	}
}

func TestSCIMComposedFiltersAndSort(t *testing.T) {
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
	mk := func(email string, active bool) {
		b := `{"userName":"` + email + `","active":` + map[bool]string{true: "true", false: "false"}[active] + `}`
		if w := do(http.MethodPost, "/scim/v2/Users", b); w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", email, w.Code, w.Body.String())
		}
	}
	mk("alice@acme.com", true)
	mk("bob@acme.com", false)
	mk("carol@other.com", true)

	count := func(filter string) int {
		w := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(filter), "")
		if w.Code != http.StatusOK {
			t.Fatalf("filter %q: code %d %s", filter, w.Code, w.Body.String())
		}
		var list struct {
			TotalResults int `json:"totalResults"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &list)
		return list.TotalResults
	}
	// AND, OR, NOT composition + precedence/grouping.
	if n := count(`emails co "acme" and active eq true`); n != 1 { // bob deactivated → alice only
		t.Fatalf("AND: want 1, got %d", n)
	}
	if n := count(`userName sw "alice" or userName sw "carol"`); n != 2 {
		t.Fatalf("OR: want 2, got %d", n)
	}
	if n := count(`not (emails co "acme")`); n != 1 { // only carol@other.com
		t.Fatalf("NOT: want 1, got %d", n)
	}
	if n := count(`active eq true and (userName sw "alice" or userName sw "zzz")`); n != 1 {
		t.Fatalf("grouped: want 1, got %d", n)
	}

	// Malformed filter → 400 invalidFilter.
	if w := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq`), ""); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "invalidFilter") {
		t.Fatalf("malformed filter: want 400 invalidFilter, got %d %s", w.Code, w.Body.String())
	}

	// Sorting: userName descending → carol, bob, alice.
	w := do(http.MethodGet, "/scim/v2/Users?sortBy=userName&sortOrder=descending", "")
	var sorted struct {
		Resources []struct {
			UserName string `json:"userName"`
		} `json:"Resources"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &sorted)
	got := []string{}
	for _, r := range sorted.Resources {
		got = append(got, r.UserName)
	}
	want := []string{"carol@other.com", "bob@acme.com", "alice@acme.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sort desc: got %v, want %v", got, want)
	}
}
