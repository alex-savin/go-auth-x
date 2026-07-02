package authx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// callMe invokes the /auth/me handler directly (the /auth group is public, so Me parses the
// session cookie itself) and decodes its always-200 JSON body.
func callMe(t *testing.T, a *Authenticator, sessionTok string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	if sessionTok != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionTok})
	}
	w := httptest.NewRecorder()
	a.wrap(a.Me)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/auth/me must always return 200, got %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /auth/me body: %v", err)
	}
	return body
}

// TestMeLocalOnlyMode verifies that in a local-only deployment (in-app password/passkey auth
// enabled, NO OIDC issuer) /auth/me reports authEnabled:true and honors the session cookie.
// Regression: Me used to branch on Enabled() (OIDC-only) instead of enforcing(), so it reported
// authEnabled:false and never parsed the cookie — frontends could not render signed-in state
// despite the request gate being fully active.
func TestMeLocalOnlyMode(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a := &Authenticator{cfg: Config{SessionSecret: secret}}
	a.SetCredentialStore(nopCreds{t: t})
	a.SetLocalEnabled(true)

	if a.Enabled() {
		t.Fatal("precondition: OIDC must be off for a local-only test")
	}
	if !a.enforcing() {
		t.Fatal("precondition: local-only mode must be enforcing")
	}

	t.Run("no session cookie: authEnabled true, authenticated false", func(t *testing.T) {
		body := callMe(t, a, "")
		if body["authEnabled"] != true {
			t.Fatalf("local-only mode must report authEnabled:true, got %v", body["authEnabled"])
		}
		if body["authenticated"] != false {
			t.Fatalf("no cookie must report authenticated:false, got %v", body["authenticated"])
		}
	})

	t.Run("valid session cookie: authenticated with identity", func(t *testing.T) {
		tok, err := mintSession(secret, "local:abc", "a@b.com", "Alice", "admin", "", []string{"g1"}, time.Now(), time.Hour)
		if err != nil {
			t.Fatalf("mintSession: %v", err)
		}
		body := callMe(t, a, tok)
		if body["authEnabled"] != true || body["authenticated"] != true {
			t.Fatalf("valid session in local-only mode must be authenticated, got %v", body)
		}
		if body["email"] != "a@b.com" || body["sub"] != "local:abc" || body["role"] != "admin" {
			t.Fatalf("identity claims must round-trip through /auth/me, got %v", body)
		}
	})

	t.Run("garbage session cookie: authEnabled true, authenticated false", func(t *testing.T) {
		body := callMe(t, a, "not-a-session")
		if body["authEnabled"] != true || body["authenticated"] != false {
			t.Fatalf("bad cookie must yield authEnabled:true authenticated:false, got %v", body)
		}
	})
}

// TestMeNoAuthConfigured verifies the wide-open (no OIDC, no local auth) deployment still reports
// authEnabled:false so the SPA hides all auth chrome.
func TestMeNoAuthConfigured(t *testing.T) {
	a := &Authenticator{cfg: Config{SessionSecret: []byte("0123456789abcdef0123456789abcdef")}}
	if a.enforcing() {
		t.Fatal("precondition: nothing is configured, gate must be off")
	}
	body := callMe(t, a, "")
	if body["authEnabled"] != false || body["authenticated"] != false {
		t.Fatalf("unconfigured auth must report both flags false, got %v", body)
	}
}
