package authx

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
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
	return a.CSRFHTTP(a.impersonationGuard(mux))
}

// impersonationGuard keeps an admin's impersonation session to looking: under /auth it may read, end
// itself, and switch the active org — not change the account. Its password, email, passkeys, second
// factor, linked sign-ins, sessions and org memberships are the user's to change, and an impersonator
// who set a password on the account could sign in to it afterwards as the user, unmarked.
func (a *Authenticator) impersonationGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !impersonationMayCall(r) {
			if sc := a.sessionOf(a.newCtx(w, r)); sc != nil && sc.ImpersonatedBy != "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "not available while impersonating a user"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// impersonationMayCall reports whether an impersonation session may make this /auth request: reads
// (but not the two links that act on the account), the sign-in entry points (they act on whoever
// signs in), ending the impersonation, the active-org switch, and the admin API (which authorizes on
// its own and refuses the session).
func impersonationMayCall(r *http.Request) bool {
	p := path.Clean("/" + r.URL.Path)
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return p != "/auth/org/invite/accept" && p != "/auth/email/change"
	}
	return csrfExempt[p] || isSocialCallback(p) || strings.HasPrefix(p, "/auth/admin/") ||
		p == "/auth/api/stop-impersonating" || p == "/auth/org/switch" || p == "/auth/logout"
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
		sc, err := parseSessionMulti(a.verifySecrets(), a.cookieValue(r, sessionCookie))
		if err == nil && a.sessionRevoked(sc) {
			err = errRevokedSession // a revoked session is treated as no session
		}
		if err != nil {
			// API-key (Bearer) principals authenticate without a session cookie — let them through so
			// RequireGroupsHTTP can authorize by the key's groups (CSRFHTTP already skips Bearer). Only
			// GLOBAL keys are a principal for the app gate; an ORG-BOUND key authorizes its org's
			// surfaces (its SCIM mount) via ValidateOrgAPIKeyScope, never the global request gate.
			// And only keys granted the app's routes (ScopeApp): a key for the admin API or a SCIM
			// mount, or one with no scopes at all, is not a principal here.
			if _, ok := a.appKey(r); ok {
				next.ServeHTTP(w, r)
				return
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
		// Bearer (API key) auth isn't cookie-based → not CSRF-able; skip — for a key that validates. Any
		// other Authorization header proves nothing, and the handler would fall back to the cookie.
		// And only without a session cookie: with both, a handler that finds the key insufficient
		// falls back to the cookie — which is then what authorizes the request, and needs the token.
		if key := bearerToken(r.Header.Get("Authorization")); key != "" && a.cookieValue(r, sessionCookie) == "" {
			if _, ok := a.lookupAPIKey(key); ok {
				next.ServeHTTP(w, r)
				return
			}
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

// cookieValue reads one of the library's cookies by its base name (see cookieName).
func (a *Authenticator) cookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(a.cookieName(name)); err == nil {
		return c.Value
	}
	return ""
}

// cookieName is the name a library cookie is sent under: its base name, or with Config.HostCookies
// that name behind the "__Host-" prefix. A browser accepts a __Host- cookie only from the host
// itself, over https, for the whole site — so a sibling subdomain can't plant one (a session of its
// own, a CSRF pair, a signup binding), which it can with a plain name.
func (a *Authenticator) cookieName(base string) string {
	if a != nil && a.cfg.HostCookies {
		return "__Host-" + base
	}
	return base
}

// CSRFCookieName is the name of the double-submit CSRF cookie the SPA reads and echoes in the
// X-CSRF-Token header: "sweep_csrf", or "__Host-sweep_csrf" with Config.HostCookies. GET /auth/config
// reports it too (csrfCookie).
func (a *Authenticator) CSRFCookieName() string { return a.cookieName(csrfCookie) }

func writeJSON(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(obj)
}

func (a *Authenticator) cookieSecureHTTP(r *http.Request) bool {
	return a.cfg.HostCookies || a.cfg.CookieSecure || strings.HasPrefix(strings.ToLower(a.cfg.AppURL), "https://") ||
		r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *Authenticator) ensureCSRFHTTP(w http.ResponseWriter, r *http.Request) {
	if a.cookieValue(r, csrfCookie) != "" {
		return
	}
	a.writeCSRFCookie(w, r)
}

func (a *Authenticator) csrfValidHTTP(r *http.Request) bool {
	cookie := a.cookieValue(r, csrfCookie)
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

// SessionOf returns the signed-in, unrevoked session of a request straight from its cookie — for
// handlers that are not behind GateHTTP (such as the oidcprovider's login step) — or nil.
func (a *Authenticator) SessionOf(r *http.Request) *SessionClaims {
	sc, err := parseSessionMulti(a.verifySecrets(), a.cookieValue(r, sessionCookie))
	if err != nil || a.sessionRevoked(sc) {
		return nil
	}
	return sc
}

// ClientIP is the request's client address, honoring X-Forwarded-For only from trusted proxies.
func (a *Authenticator) ClientIP(r *http.Request) string { return a.clientIP(r) }

// CSRFValid reports whether a state-changing request carries the double-submit CSRF token (and an
// allowed Origin) — for handlers outside /api and /auth that CSRFHTTP does not cover.
func (a *Authenticator) CSRFValid(r *http.Request) bool { return a.csrfValidHTTP(r) }
