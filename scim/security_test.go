package scim

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
