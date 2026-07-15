package authx

import (
	"net/http"
	"net/url"
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
	"/auth/email-otp/send":         true, // pre-session: emails a numeric code
	"/auth/email-otp/verify":       true, // pre-session: redeems the code to establish the session
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

// originAllowed is defense-in-depth layered ON TOP of the double-submit token: on a state-changing
// request it requires the Origin (or, absent that, the Referer's origin) to match an allow-list of
// AppURL + Config.TrustedOrigins. It FAILS OPEN — a request with neither header, or an empty
// allow-list, passes — so the token stays the primary check and no legitimate same-origin POST is
// rejected (important in local-only mode, where AppURL may be unset). Only a PRESENT-and-mismatched
// origin is refused, which uniquely blocks the sibling-subdomain cookie-injection CSRF variant that
// SameSite=Lax (an eTLD+1-scoped signal) does not.
func (a *Authenticator) originAllowed(r *http.Request) bool {
	// Fetch Metadata (widely supported): reject a request the browser itself marks as genuinely
	// cross-site, even when no Origin allow-list is configured. This closes cross-site login-CSRF on the
	// token-exempt entry points (e.g. /auth/email-otp/verify) in the local-only default. A missing or
	// non-cross-site value falls through to the Origin allow-list below (which fails open when unset), so
	// this only ever ADDS a rejection — no legitimate same-origin request is affected.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil && u.Scheme != "" && u.Host != "" {
				origin = u.Scheme + "://" + u.Host
			}
		}
	}
	if origin == "" {
		return true // nothing to check — the token remains the primary defense
	}
	allowed := a.trustedOrigins()
	if len(allowed) == 0 {
		return true // no allow-list configured
	}
	for _, o := range allowed {
		if o != "" && strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

// trustedOrigins is AppURL's origin plus any Config.TrustedOrigins.
func (a *Authenticator) trustedOrigins() []string {
	var out []string
	if b := a.baseURL(); b != "" {
		out = append(out, b)
	}
	return append(out, a.cfg.TrustedOrigins...)
}
