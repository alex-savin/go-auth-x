package authx

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// --- net/http integration ---
//
// The whole library is net/http — no framework dependency. Mount Handler() in any mux and gate your
// own routes with GateHTTP / CSRFHTTP. The session + CSRF cookies are shared (same names + HMAC
// secret), so a login served by Handler() is recognized by GateHTTP.

type ctxKey int

const sessionCtxKey ctxKey = 0

// Handler returns the /auth/* endpoints as a standard http.Handler (a net/http ServeMux wrapped in
// CSRF enforcement). Mount it in any router — no framework dependency:
//
//	mux.Handle("/auth/", authn.Handler())   // net/http, chi, echo, ...
func (a *Authenticator) Handler() http.Handler {
	mux := http.NewServeMux()
	a.routes(mux)
	return a.CSRFHTTP(mux)
}

// GateHTTP is net/http middleware that enforces a valid session: public paths pass; missing/invalid
// sessions get a 401 JSON for /api and /ws, else a redirect to the branded landing. A valid API-key
// Bearer is also admitted (for RequireGroupsHTTP downstream). On success it stashes the session in the
// request context (see SessionFromRequest) and ensures a CSRF cookie. No-op when auth isn't enforced.
func (a *Authenticator) GateHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enforcing() {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if a.publicPath(p) {
			next.ServeHTTP(w, r)
			return
		}
		sc, err := parseSessionMulti(a.verifySecrets(), cookieValue(r, sessionCookie))
		if err == nil && a.sessionRevoked(sc) {
			err = errRevokedSession // a revoked session is treated as no session
		}
		if err != nil {
			// API-key (Bearer) principals authenticate without a session cookie — let them through so
			// RequireGroupsHTTP can authorize by the key's groups (CSRFHTTP already skips Bearer).
			if key := bearerToken(r.Header.Get("Authorization")); key != "" {
				if _, ok := a.ValidateAPIKey(key); ok {
					next.ServeHTTP(w, r)
					return
				}
			}
			if p == "/api" || p == "/ws" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/ws/") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			} else {
				// Preserve the full target (path + query) so the post-login redirect lands correctly.
				http.Redirect(w, r, "/welcome?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			}
			return
		}
		a.ensureCSRFHTTP(w, r)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sc)))
	})
}

// CSRFHTTP is net/http middleware that enforces the double-submit CSRF token on state-changing
// /api and /auth requests, skipping the unauthenticated entry points and social callbacks.
func (a *Authenticator) CSRFHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enforcing() {
			next.ServeHTTP(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		// Social callbacks are legitimately cross-site (Apple's form_post arrives from Apple's origin) and
		// are protected by the OAuth `state` parameter — skip both the token AND the origin check.
		if isSocialCallback(p) {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer (API key) auth isn't cookie-based → not CSRF-able; skip.
		if bearerToken(r.Header.Get("Authorization")) != "" {
			next.ServeHTTP(w, r)
			return
		}
		// The unauthenticated entry points (login/reset/OTP-verify/…) can't carry a double-submit token,
		// but the trusted-origins check still applies as defense-in-depth against a cross-site login-CSRF
		// (e.g. logging a victim into the attacker's account via /auth/email-otp/verify). It fails open
		// when no allow-list is configured or no Origin/Referer is present, so the default is unaffected.
		if csrfExempt[p] {
			if !a.originAllowed(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if !a.csrfValidHTTP(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid or missing CSRF token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SessionFromRequest returns the authenticated subject + email from a request gated by GateHTTP.
func SessionFromRequest(r *http.Request) (sub, email string, ok bool) {
	if sc, is := r.Context().Value(sessionCtxKey).(*SessionClaims); is && sc != nil {
		return sc.Subject, sc.Email, true
	}
	return "", "", false
}

// --- net/http cookie/JSON helpers ---

func cookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(obj)
}

func (a *Authenticator) cookieSecureHTTP(r *http.Request) bool {
	return a.cfg.CookieSecure || r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *Authenticator) ensureCSRFHTTP(w http.ResponseWriter, r *http.Request) {
	if cookieValue(r, csrfCookie) != "" {
		return
	}
	a.writeCSRFCookie(w, r)
}

func (a *Authenticator) csrfValidHTTP(r *http.Request) bool {
	cookie := cookieValue(r, csrfCookie)
	header := r.Header.Get(csrfHeader)
	if cookie == "" || header == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) != 1 {
		return false
	}
	// Defense-in-depth: also require a present Origin/Referer to be allow-listed (fails open otherwise).
	return a.originAllowed(r)
}
