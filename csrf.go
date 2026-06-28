package authx

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	csrfCookie = "sweep_csrf"
	csrfHeader = "X-CSRF-Token"
)

// csrfExempt are the unauthenticated auth entry points: they run BEFORE the user has a session
// or CSRF token (they establish the session) or carry their own one-time token (password reset
// confirm, email verify). Requiring a double-submit token on them is impossible and pointless,
// so they are skipped by the CSRF guard. Everything else state-changing under /auth and /api is
// enforced.
var csrfExempt = map[string]bool{
	"/auth/signup":                 true,
	"/auth/restore":                true, // recovery request (anti-enumeration, always 200)
	"/auth/callback":               true, // OIDC redirect target
	"/auth/password/signup":        true,
	"/auth/password/login":         true,
	"/auth/password/reset/request": true,
	"/auth/password/reset/confirm": true, // proven by the reset token in the body
	"/auth/email/request":          true,
	"/auth/webauthn/login/begin":   true, // discoverable login — no session yet
	"/auth/webauthn/login/finish":  true,
}

// issueCSRF sets a fresh non-HttpOnly CSRF cookie that the SPA reads and echoes back in the
// X-CSRF-Token header on state-changing requests (double-submit). Called on every login.
// SameSite=Lax already blocks cross-site form POSTs; this closes the residual gap.
func (a *Authenticator) issueCSRF(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	// Not HttpOnly: the SPA must read it to echo it in the header.
	c.SetCookie(csrfCookie, randToken(), int(sessionTTL.Seconds()), "/", "", a.cookieSecure(c), false)
}

// ensureCSRF sets the CSRF cookie only if the request doesn't already carry one, so an
// authenticated session always has a token to echo without rotating it mid-session (which would
// break in-flight requests). Called by the auth middleware on every gated request.
func (a *Authenticator) ensureCSRF(c *gin.Context) {
	if v, _ := c.Cookie(csrfCookie); v == "" {
		a.issueCSRF(c)
	}
}

// csrfValid reports whether the request carries matching CSRF cookie + header (constant time).
func (a *Authenticator) csrfValid(c *gin.Context) bool {
	cookie, _ := c.Cookie(csrfCookie)
	header := c.GetHeader(csrfHeader)
	if cookie == "" || header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) == 1
}

// CSRFMiddleware enforces the double-submit CSRF token on state-changing (non-safe) requests to
// /api and /auth, skipping the unauthenticated auth entry points (csrfExempt). It is a no-op when
// auth isn't enforced and for safe methods. SameSite=Lax already blocks cross-site form POSTs;
// this closes the residual gap (custom-header requests an attacker's origin can't forge because it
// can neither read the cookie nor set the X-CSRF-Token header cross-origin).
func (a *Authenticator) CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.enforcing() {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		p := c.Request.URL.Path
		if !strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/auth/") {
			c.Next()
			return
		}
		if csrfExempt[p] {
			c.Next()
			return
		}
		if !a.csrfValid(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid or missing CSRF token"})
			return
		}
		c.Next()
	}
}
