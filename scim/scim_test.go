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
}
