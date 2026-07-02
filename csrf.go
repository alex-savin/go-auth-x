package authx

import (
	"net/http"
	"strings"
)

const (
	csrfCookie = "sweep_csrf"
	csrfHeader = "X-CSRF-Token"
)

// isSocialCallback reports whether p is a social provider's OAuth callback (/auth/social/*/callback).
// These are cross-site redirects/POSTs (notably Apple's form_post) that cannot carry a double-submit
// CSRF token; they're protected by the OAuth `state` parameter instead, so CSRF is skipped. The exact
// provider slug is dynamic, so this can't live in the exact-match csrfExempt map.
func isSocialCallback(p string) bool {
	return strings.HasPrefix(p, "/auth/social/") && strings.HasSuffix(p, "/callback")
}

// csrfExempt are the unauthenticated auth entry points: they run BEFORE the user has a session or
// CSRF token (they establish the session) or carry their own one-time token (password reset
// confirm, email verify). Requiring a double-submit token on them is impossible and pointless, so
// they are skipped by the CSRF guard. Everything else state-changing under /auth and /api is
// enforced (see CSRFHTTP in httpadapter.go).
var csrfExempt = map[string]bool{
	"/auth/callback":               true, // OIDC redirect target
	"/auth/password/signup":        true,
	"/auth/password/login":         true,
	"/auth/password/reset/request": true,
	"/auth/password/reset/confirm": true, // proven by the reset token in the body
	"/auth/email/request":          true,
	"/auth/webauthn/login/begin":   true, // discoverable login — no session yet
	"/auth/webauthn/login/finish":  true,
	"/auth/2fa/verify":             true, // pre-session (mid-login); gated by the code + signed pending cookie
	"/auth/2fa/webauthn/begin":     true, // pre-session; gated by the signed pending cookie
	"/auth/2fa/webauthn/finish":    true, // pre-session; gated by the pending cookie + passkey assertion
}

// writeCSRFCookie writes a fresh non-HttpOnly double-submit CSRF cookie. Its lifetime matches the
// longest session (remember-me) so a mid-session POST never fails because the token expired first.
// Not HttpOnly: the SPA must read it to echo it in the X-CSRF-Token header. Single source of truth
// for both issueCSRF (login) and ensureCSRFHTTP (the gate).
func (a *Authenticator) writeCSRFCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: randToken(), MaxAge: int(rememberTTL.Seconds()), Path: "/",
		Secure: a.cookieSecureHTTP(r), HttpOnly: false, SameSite: http.SameSiteLaxMode,
	})
}

// issueCSRF sets a fresh CSRF cookie (called on every login).
func (a *Authenticator) issueCSRF(c *reqCtx) { a.writeCSRFCookie(c.w, c.Request) }
