package authx

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// --- net/http integration ---
//
// The handlers are Gin internally, but consumers don't need Gin: mount Handler() in any mux and
// gate your own routes with GateHTTP / CSRFHTTP (net/http middleware). The session + CSRF cookies
// are shared (same names + HMAC secret), so a login served by Handler() is recognized by GateHTTP.

type ctxKey int

const sessionCtxKey ctxKey = 0

// Handler returns the /auth/* endpoints as a standard http.Handler (an internal Gin engine with
// Recovery, trusted proxies, and CSRF enforcement). Mount it in any router:
//
//	mux.Handle("/auth/", authn.Handler())   // net/http, chi, echo, ...
func (a *Authenticator) Handler() http.Handler {
	r := gin.New()
	_ = r.SetTrustedProxies(TrustedProxies())
	r.Use(gin.Recovery())
	r.Use(a.CSRFMiddleware())
	a.Register(r)
	return r
}

// GateHTTP is net/http middleware that enforces a valid session (mirrors Middleware): public
// paths pass; missing/invalid sessions get a 401 JSON for /api and /ws, else a redirect to the
// branded landing. On success it stashes the session in the request context (see
// SessionFromRequest) and ensures a CSRF cookie. No-op when auth isn't enforced.
func (a *Authenticator) GateHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enforcing() {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if isPublicPath(p) {
			next.ServeHTTP(w, r)
			return
		}
		sc, err := parseSession(a.cfg.SessionSecret, cookieValue(r, sessionCookie))
		if err != nil {
			if strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/ws") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			} else {
				http.Redirect(w, r, "/welcome?next="+url.QueryEscape(p), http.StatusFound)
			}
			return
		}
		a.ensureCSRFHTTP(w, r)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sc)))
	})
}

// CSRFHTTP is net/http middleware that enforces the double-submit CSRF token on state-changing
// /api and /auth requests (mirrors CSRFMiddleware), skipping the unauthenticated entry points.
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
		if (!strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/auth/")) || csrfExempt[p] {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer (API key) auth isn't cookie-based → not CSRF-able; skip.
		if bearerToken(r.Header.Get("Authorization")) != "" {
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
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: randToken(), Path: "/", MaxAge: int(sessionTTL.Seconds()),
		Secure: a.cookieSecureHTTP(r), HttpOnly: false, SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) csrfValidHTTP(r *http.Request) bool {
	cookie := cookieValue(r, csrfCookie)
	header := r.Header.Get(csrfHeader)
	if cookie == "" || header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) == 1
}
