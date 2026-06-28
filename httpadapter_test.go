package authx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPAdapter(t *testing.T) {
	a := &Authenticator{cfg: Config{SessionSecret: []byte("0123456789abcdef0123456789abcdef")}}

	// Handler() builds a mountable http.Handler.
	if a.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}

	// csrfValidHTTP: matching cookie+header passes; a mismatch (or a missing one) fails.
	ok := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	ok.AddCookie(&http.Cookie{Name: csrfCookie, Value: "tok"})
	ok.Header.Set(csrfHeader, "tok")
	if !a.csrfValidHTTP(ok) {
		t.Fatal("csrfValidHTTP should accept matching cookie+header")
	}
	bad := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	bad.AddCookie(&http.Cookie{Name: csrfCookie, Value: "tok"})
	bad.Header.Set(csrfHeader, "different")
	if a.csrfValidHTTP(bad) {
		t.Fatal("csrfValidHTTP should reject a mismatched header")
	}

	// SessionFromRequest reads the context GateHTTP sets (use a real minted/parsed session).
	tok, err := mintSession(a.cfg.SessionSecret, "local:x", "x@y.com", "X", "", "", nil, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("mintSession: %v", err)
	}
	sc, err := parseSession(a.cfg.SessionSecret, tok)
	if err != nil {
		t.Fatalf("parseSession: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(context.WithValue(context.Background(), sessionCtxKey, sc))
	if sub, email, got := SessionFromRequest(req); !got || sub != "local:x" || email != "x@y.com" {
		t.Fatalf("SessionFromRequest: %q %q %v", sub, email, got)
	}

	// With auth not enforced, CSRFHTTP passes everything through.
	called := false
	a.CSRFHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/x", nil))
	if !called {
		t.Fatal("CSRFHTTP should be a no-op when auth is disabled")
	}
}
