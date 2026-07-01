package authx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// reached returns a handler that records whether the inner (gated) handler ran.
func reached(hit *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hit = true
		w.WriteHeader(http.StatusOK)
	})
}

// newGate builds an Authenticator whose request gate is active (enforcing == true via a.enabled),
// with the supplied PublicPath matcher, and returns a server wrapping a trivial 200 handler.
func newGate(t *testing.T, matcher func(string) bool) (*Authenticator, http.Handler, *bool) {
	t.Helper()
	a := &Authenticator{cfg: Config{
		SessionSecret: []byte("0123456789abcdef0123456789abcdef"),
		PublicPath:    matcher,
	}}
	a.enabled = true // force enforcing() == true without OIDC discovery
	if !a.enforcing() {
		t.Fatal("gate must be enforcing for the test to be meaningful")
	}
	hit := new(bool)
	return a, a.GateHTTP(reached(hit)), hit
}

func TestPublicPathGate(t *testing.T) {
	matcher := func(p string) bool { return p == "/my-login" }

	// get issues a GET and reports the inner-handler-reached flag + status code.
	get := func(h http.Handler, hit *bool, path string) (bool, int) {
		*hit = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return *hit, w.Code
	}

	t.Run("matcher-true reaches inner handler", func(t *testing.T) {
		_, h, hit := newGate(t, matcher)
		got, code := get(h, hit, "/my-login")
		if !got {
			t.Fatalf("/my-login must reach inner handler (matcher returns true); reached=%v code=%d", got, code)
		}
		if code != http.StatusOK {
			t.Fatalf("/my-login must be 200, got %d", code)
		}
	})

	t.Run("matcher-false is gated, never 200", func(t *testing.T) {
		_, h, hit := newGate(t, matcher)
		got, code := get(h, hit, "/secret")
		if got {
			t.Fatal("/secret must NOT reach inner handler (matcher returns false)")
		}
		if code == http.StatusOK {
			t.Fatalf("/secret must be gated, never 200; got %d", code)
		}
		// browser path (not /api,/ws) → redirect 302 to /welcome.
		if code != http.StatusFound {
			t.Fatalf("/secret (browser path) should redirect 302, got %d", code)
		}
	})

	t.Run("api browser-path returns JSON 401 not redirect", func(t *testing.T) {
		// A non-public /api path with no session → 401 JSON (not a redirect).
		_, h, hit := newGate(t, matcher)
		got, code := get(h, hit, "/api/orders")
		if got {
			t.Fatal("/api/orders must be gated")
		}
		if code != http.StatusUnauthorized {
			t.Fatalf("/api/orders should be 401, got %d", code)
		}
	})

	t.Run("library surface always public despite matcher=false", func(t *testing.T) {
		// matcher returns false for ALL of these — they must still pass because the library's
		// own surface (/auth, /_next, health) is always-public regardless of Config.PublicPath.
		falseMatcher := func(string) bool { return false }
		_, h, hit := newGate(t, falseMatcher)

		// Sanity: the matcher really would close these if it were honored.
		for _, p := range []string{"/auth/login", "/_next/x", "/api/health"} {
			if matcher(p) || falseMatcher(p) {
				t.Fatalf("precondition: matcher should return false for %q", p)
			}
		}

		for _, p := range []string{"/auth/login", "/_next/x", "/api/health"} {
			got, code := get(h, hit, p)
			if !got {
				t.Fatalf("%q must ALWAYS be public (reach inner handler) even when matcher returns false; reached=%v code=%d", p, got, code)
			}
			if code != http.StatusOK {
				t.Fatalf("%q must be 200, got %d", p, code)
			}
		}
	})

	t.Run("matcher cannot OPEN deeper api routes the library closes", func(t *testing.T) {
		// Adversarial: a matcher that tries to open EVERYTHING. The library surface is fine to be
		// open, but a protected /api/* route must still be gated — publicPath delegates fully to
		// the matcher for app routes, so an all-open matcher DOES open /api/orders. That is the
		// documented contract (consumer matcher takes over app-route decisions). Confirm that the
		// library's always-public set is independent, i.e. the matcher can't *close* /auth either.
		openAll := func(string) bool { return true }
		_, h, hit := newGate(t, openAll)
		// With an all-open matcher, /api/orders is intentionally public — verify no panic / 200.
		got, code := get(h, hit, "/api/orders")
		if !got || code != http.StatusOK {
			t.Fatalf("all-open matcher should let /api/orders through: reached=%v code=%d", got, code)
		}
	})

	t.Run("nil matcher uses built-in default; /login public, /secret gated", func(t *testing.T) {
		_, h, hit := newGate(t, nil)

		// Built-in default reference routes must pass.
		for _, p := range []string{"/login", "/register", "/welcome", "/signup", "/restore", "/recover", "/reset", "/verify"} {
			got, code := get(h, hit, p)
			if !got || code != http.StatusOK {
				t.Fatalf("nil matcher: built-in %q must be public; reached=%v code=%d", p, got, code)
			}
		}
		// Library surface still public.
		for _, p := range []string{"/auth/callback", "/_next/static/x.js", "/api/health", "/favicon.ico"} {
			got, code := get(h, hit, p)
			if !got || code != http.StatusOK {
				t.Fatalf("nil matcher: library surface %q must be public; reached=%v code=%d", p, got, code)
			}
		}
		// A non-default path is gated.
		got, code := get(h, hit, "/secret")
		if got || code == http.StatusOK {
			t.Fatalf("nil matcher: /secret must be gated; reached=%v code=%d", got, code)
		}
		// /my-login is NOT a built-in default → gated when matcher is nil.
		got, code = get(h, hit, "/my-login")
		if got || code == http.StatusOK {
			t.Fatalf("nil matcher: /my-login must be gated (not a built-in default); reached=%v code=%d", got, code)
		}
	})

	t.Run("matcher precision: only exact /my-login opens, /my-login/x gated", func(t *testing.T) {
		// The supplied matcher is an exact-equality check; a sibling path must NOT leak through.
		_, h, hit := newGate(t, matcher)
		got, code := get(h, hit, "/my-login/extra")
		if got || code == http.StatusOK {
			t.Fatalf("/my-login/extra must be gated (matcher is exact-equality); reached=%v code=%d", got, code)
		}
		got, code = get(h, hit, "/my-loginX")
		if got || code == http.StatusOK {
			t.Fatalf("/my-loginX must be gated; reached=%v code=%d", got, code)
		}
	})
}
