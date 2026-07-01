package authx

import "net/http"

const (
	csrfCookie = "sweep_csrf"
	csrfHeader = "X-CSRF-Token"
)

// csrfExempt are the unauthenticated auth entry points: they run BEFORE the user has a session or
// CSRF token (they establish the session) or carry their own one-time token (password reset
// confirm, email verify). Requiring a double-submit token on them is impossible and pointless, so
// they are skipped by the CSRF guard. Everything else state-changing under /auth and /api is
// enforced (see CSRFHTTP in httpadapter.go).
var csrfExempt = map[string]bool{
	"/auth/signup":                 true,
	"/auth/restore":                true,
	"/auth/callback":               true, // OIDC redirect target
	"/auth/password/signup":        true,
	"/auth/password/login":         true,
	"/auth/password/reset/request": true,
	"/auth/password/reset/confirm": true, // proven by the reset token in the body
	"/auth/email/request":          true,
	"/auth/webauthn/login/begin":   true, // discoverable login — no session yet
	"/auth/webauthn/login/finish":  true,
	"/auth/2fa/verify":             true, // pre-session (mid-login); gated by the code + signed pending cookie
}

// issueCSRF sets a fresh non-HttpOnly CSRF cookie that the SPA reads and echoes back in the
// X-CSRF-Token header on state-changing requests (double-submit). Called on every login.
func (a *Authenticator) issueCSRF(c *reqCtx) {
	// Not HttpOnly: the SPA must read it to echo it in the header.
	http.SetCookie(c.w, &http.Cookie{
		Name: csrfCookie, Value: randToken(), MaxAge: int(sessionTTL.Seconds()), Path: "/",
		Secure: a.cookieSecureHTTP(c.Request), HttpOnly: false, SameSite: http.SameSiteLaxMode,
	})
}
