package oidcprovider_test

import (
	"net/http"
	"testing"
)

// No endpoint lets another origin read a response made with the user's cookies: zitadel's default
// CORS policy echoed any Origin back with Access-Control-Allow-Credentials. Browser clients still
// get "*" (and a preflight answer) for the token endpoint and friends.
func TestCORSNeverCredentialed(t *testing.T) {
	h := setup(t)
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	check := func(method, path string, hdr map[string]string) string {
		t.Helper()
		req, _ := http.NewRequest(method, h.srv.URL+path, nil)
		req.Header.Set("Origin", "https://evil.example")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := h.web.Do(req) // the signed-in browser: its session cookie goes along
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		acao := res.Header.Get("Access-Control-Allow-Origin")
		if acac := res.Header.Get("Access-Control-Allow-Credentials"); acac != "" {
			t.Errorf("%s %s: Access-Control-Allow-Credentials %q (Allow-Origin %q)", method, path, acac, acao)
		}
		if acao != "" && acao != "*" {
			t.Errorf("%s %s: Access-Control-Allow-Origin %q, want \"*\" or none", method, path, acao)
		}
		return acao
	}
	for _, p := range []string{
		"/oauth/authorize?client_id=x&response_type=code", "/oauth/end_session", "/oauth/token", "/oauth/userinfo",
		"/oauth/introspect", "/oauth/revoke", "/oauth/keys", "/oauth/", "/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server", "/oauth/consent?id=x", "/oauth/login",
	} {
		check(http.MethodGet, p, nil)
	}
	if acao := check(http.MethodOptions, "/oauth/token", map[string]string{
		"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type",
	}); acao != "*" {
		t.Errorf("token preflight: Access-Control-Allow-Origin %q, want \"*\" (browser clients exchange codes)", acao)
	}
	if acao := check(http.MethodGet, "/oauth/keys", nil); acao != "*" {
		t.Errorf("keys: Access-Control-Allow-Origin %q, want \"*\"", acao)
	}
}
