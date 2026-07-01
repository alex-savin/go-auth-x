package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alex-savin/go-auth-x/store/memory"
)

// adversarialHarness spins the SCIM server over a memory store with a bearer check.
func adversarialHarness(t *testing.T) func(method, path, body string) *httptest.ResponseRecorder {
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

// totalResults pulls the totalResults count out of a ListResponse body.
func totalResults(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var list struct {
		TotalResults int `json:"totalResults"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v body=%s", err, w.Body.String())
	}
	return list.TotalResults
}

// TestAdversarialSCIMFiltersBulk attacks the SCIM filters + /Bulk claims.
func TestAdversarialSCIMFiltersBulk(t *testing.T) {
	do := adversarialHarness(t)

	// First, a guard: the bearer check must actually reject a bad token, otherwise
	// every other assertion is meaningless.
	{
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer WRONG")
		w := httptest.NewRecorder()
		dir := memory.New()
		srv := NewServer(dir, func(tok string) bool { return tok == "secret" })
		http.StripPrefix("/scim/v2", srv.Handler()).ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("bearer guard: bad token should be 401, got %d", w.Code)
		}
	}

	// --- (a) co/sw/pr operators ---------------------------------------------
	// Provision two users with distinct emails.
	for _, em := range []string{"alice@acme.com", "bob@example.org"} {
		body := fmt.Sprintf(`{"userName":%q,"active":true,"emails":[{"value":%q,"primary":true}]}`, em, em)
		if w := do(http.MethodPost, "/scim/v2/Users", body); w.Code != http.StatusCreated {
			t.Fatalf("provision %s: want 201, got %d body=%s", em, w.Code, w.Body.String())
		}
	}

	filterCases := []struct {
		filter string
		want   int
		desc   string
	}{
		{`emails co "acme"`, 1, "co matches only alice's domain"},
		{`emails co "example"`, 1, "co matches only bob's domain"},
		{`emails co ".com"`, 1, "co substring across email"},
		{`userName sw "alice"`, 1, "sw prefix matches alice"},
		{`userName sw "bob"`, 1, "sw prefix matches bob"},
		{`userName sw "ali"`, 1, "sw partial prefix"},
		{`userName pr`, 2, "pr present matches both"},
		{`userName co "nobody"`, 0, "non-match returns 0"},
		{`userName sw "zzz"`, 0, "sw non-match returns 0"},
		{`userName eq "alice@acme.com"`, 1, "eq exact match"},
		{`userName eq "ALICE@ACME.COM"`, 1, "eq is case-insensitive per matchStr"},
	}
	for _, c := range filterCases {
		w := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(c.filter), "")
		if w.Code != http.StatusOK {
			t.Fatalf("filter %q (%s): code %d body=%s", c.filter, c.desc, w.Code, w.Body.String())
		}
		if got := totalResults(t, w); got != c.want {
			t.Fatalf("filter %q (%s): want %d, got %d", c.filter, c.desc, c.want, got)
		}
	}

	// --- (b) Bulk must NOT abort on a failing op ----------------------------
	// op1 = invalid create (missing userName -> 400), op2 = valid create (-> 201).
	bulkMixed := `{"Operations":[
		{"method":"POST","path":"/Users","data":{"active":true}},
		{"method":"POST","path":"/Users","data":{"userName":"carol@acme.com","active":true}}
	]}`
	w := do(http.MethodPost, "/scim/v2/Bulk", bulkMixed)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk mixed: BulkResponse must be 200, got %d body=%s", w.Code, w.Body.String())
	}
	var br struct {
		Operations []map[string]any `json:"Operations"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatalf("bulk decode: %v body=%s", err, w.Body.String())
	}
	if len(br.Operations) != 2 {
		t.Fatalf("bulk did not continue past the failing op: want 2 op results, got %d (%+v)", len(br.Operations), br.Operations)
	}
	statuses := []string{
		fmt.Sprint(br.Operations[0]["status"]),
		fmt.Sprint(br.Operations[1]["status"]),
	}
	have400, have201 := false, false
	for _, st := range statuses {
		if st == "400" {
			have400 = true
		}
		if st == "201" {
			have201 = true
		}
	}
	if !have400 || !have201 {
		t.Fatalf("bulk per-op statuses must contain BOTH 400 and 201; got %v", statuses)
	}
	// Order check: the invalid op is first, valid op is second.
	if statuses[0] != "400" {
		t.Fatalf("op1 (invalid create) should be 400, got %s", statuses[0])
	}
	if statuses[1] != "201" {
		t.Fatalf("op2 (valid create) should be 201, got %s", statuses[1])
	}
	// And the valid op must have actually persisted carol.
	cw := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "carol@acme.com"`), "")
	if got := totalResults(t, cw); got != 1 {
		t.Fatalf("valid bulk op did not persist carol: want 1, got %d", got)
	}

	// --- (c) nested Bulk op rejected per-op (400, not dispatched) -----------
	// Use a sentinel: if the nested /Bulk were dispatched into the mux it would
	// itself parse and return 200 with an Operations body. We assert 400 + the
	// "unsupported bulk operation" detail, and that the inner create did NOT run.
	nested := `{"Operations":[
		{"method":"POST","path":"/Bulk","data":{"Operations":[{"method":"POST","path":"/Users","data":{"userName":"smuggled@acme.com","active":true}}]}}
	]}`
	nw := do(http.MethodPost, "/scim/v2/Bulk", nested)
	if nw.Code != http.StatusOK {
		t.Fatalf("nested bulk outer: BulkResponse should be 200, got %d body=%s", nw.Code, nw.Body.String())
	}
	var nbr struct {
		Operations []map[string]any `json:"Operations"`
	}
	if err := json.Unmarshal(nw.Body.Bytes(), &nbr); err != nil {
		t.Fatalf("nested bulk decode: %v body=%s", err, nw.Body.String())
	}
	if len(nbr.Operations) != 1 {
		t.Fatalf("nested bulk: want 1 op result, got %d", len(nbr.Operations))
	}
	if st := fmt.Sprint(nbr.Operations[0]["status"]); st != "400" {
		t.Fatalf("nested /Bulk op must be rejected with 400, got %s (%+v)", st, nbr.Operations[0])
	}
	// The smuggled inner create must NOT have been dispatched.
	sw := do(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "smuggled@acme.com"`), "")
	if got := totalResults(t, sw); got != 0 {
		t.Fatalf("nested /Bulk recursed: smuggled user was created (want 0, got %d)", got)
	}
	// Try path variants that could bypass the Trim("/")+EqualFold check.
	for _, p := range []string{"Bulk", "/Bulk", "/Bulk/", "//Bulk", "bUlK"} {
		nestedV := fmt.Sprintf(`{"Operations":[{"method":"POST","path":%q,"data":{"Operations":[]}}]}`, p)
		vw := do(http.MethodPost, "/scim/v2/Bulk", nestedV)
		var vbr struct {
			Operations []map[string]any `json:"Operations"`
		}
		_ = json.Unmarshal(vw.Body.Bytes(), &vbr)
		if len(vbr.Operations) != 1 {
			t.Fatalf("nested variant %q: want 1 op result, got %d body=%s", p, len(vbr.Operations), vw.Body.String())
		}
		if st := fmt.Sprint(vbr.Operations[0]["status"]); st != "400" {
			t.Fatalf("nested /Bulk variant %q must be rejected with 400, got %s", p, st)
		}
	}

	// --- (d) >100 operations returns 413 ------------------------------------
	// Exactly 100 must be accepted (boundary), 101 must be 413.
	build := func(n int) string {
		var b strings.Builder
		b.WriteString(`{"Operations":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"method":"POST","path":"/Users","data":{"userName":"u%d@cap.com","active":true}}`, i)
		}
		b.WriteString(`]}`)
		return b.String()
	}
	if w := do(http.MethodPost, "/scim/v2/Bulk", build(100)); w.Code != http.StatusOK {
		t.Fatalf("exactly 100 ops (== cap) must be allowed: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/scim/v2/Bulk", build(101)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf(">100 ops: want 413, got %d body=%s", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/scim/v2/Bulk", build(500)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("500 ops: want 413, got %d body=%s", w.Code, w.Body.String())
	}
}
