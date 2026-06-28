package authx

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	sessionCookie = "sweep_session"
	flowCookie    = "sweep_oidc_flow"
	ctxSessionKey = "authSession"
)

// Middleware gates every request once auth is enabled. /auth/* and /api/health stay
// public; everything else requires a valid session. Unauthenticated API/WS calls get
// a 401 JSON (so the SPA's fetch layer can react); browser navigations are redirected
// to the login flow. It is a no-op when auth is disabled.
func (a *Authenticator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.enforcing() {
			c.Next()
			return
		}
		p := c.Request.URL.Path
		if isPublicPath(p) {
			c.Next()
			return
		}
		tok, _ := c.Cookie(sessionCookie)
		sc, err := parseSession(a.cfg.SessionSecret, tok)
		if err != nil {
			if strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/ws") {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			} else {
				// Browser navigation → our own branded landing (Sign in / Create account),
				// not straight to the IdP. The landing's "Sign in" preserves the next path.
				c.Redirect(http.StatusFound, "/welcome?next="+url.QueryEscape(p))
				c.Abort()
			}
			return
		}
		c.Set(ctxSessionKey, sc)
		// Every authenticated session gets a CSRF cookie (idempotent — only set when absent),
		// regardless of how it was minted (OIDC callback, password, passkey, magic-link). This
		// decouples CSRF availability from the login path so enforcement can't false-positive.
		a.ensureCSRF(c)
		c.Next()
	}
}

// enforcing reports whether the request gate is active. Unlike Enabled() (OIDC only), this is
// true whenever ANY auth method is live — OIDC OR in-app local auth — so a password/passkey-only
// deployment (no OIDC issuer) is still gated instead of silently wide open.
func (a *Authenticator) enforcing() bool {
	return a != nil && (a.enabled || a.LocalEnabled())
}

// TrustedProxies returns the proxy IPs/CIDRs gin should trust when extracting the client IP from
// X-Forwarded-For, read from TRUSTED_PROXIES (comma-separated) or a private-range default that
// matches the usual reverse-proxy-on-a-private-network deployment. Without it gin trusts ALL
// proxies, letting a client spoof X-Forwarded-For to defeat per-IP rate limits.
func TrustedProxies() []string {
	if v := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES")); v != "" {
		return splitCSV(v)
	}
	return []string{"127.0.0.1/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
}

// isPublicPath lists the routes reachable without a session: the auth flow itself and
// the container healthcheck.
func isPublicPath(p string) bool {
	// Static assets must be reachable without a session — the public React auth pages
	// (/login etc.) load their CSS/JS from /_next/*, and gating those would 302 them to the
	// login flow, leaving the page unstyled and un-hydrated.
	if strings.HasPrefix(p, "/_next/") || strings.HasPrefix(p, "/auth/") {
		return true
	}
	switch p {
	case "/api/health", "/favicon.ico", "/signup", "/welcome", "/restore",
		// In-app auth React routes (login flow + self-service entry).
		"/login", "/register", "/recover", "/reset", "/verify":
		return true
	}
	return false
}

// SessionSubject returns the authenticated subject + email from the request context
// (set by Middleware on gated routes). Used by the multi-tenant layer to resolve the
// current user.
func SessionSubject(c *gin.Context) (sub, email string, ok bool) {
	if sc := sessionFrom(c); sc != nil {
		return sc.Subject, sc.Email, true
	}
	return "", "", false
}

// sessionFrom returns the session attached by the middleware, if any.
func sessionFrom(c *gin.Context) *SessionClaims {
	if v, ok := c.Get(ctxSessionKey); ok {
		if sc, ok := v.(*SessionClaims); ok {
			return sc
		}
	}
	return nil
}

// cookieSecure reports whether cookies should carry the Secure flag (under TLS, behind an
// https proxy, or forced via COOKIE_SECURE) — so local http dev still works.
func (a *Authenticator) cookieSecure(c *gin.Context) bool {
	return a.cfg.CookieSecure ||
		c.Request.TLS != nil ||
		strings.EqualFold(c.Request.Header.Get("X-Forwarded-Proto"), "https")
}

// setCookie writes a hardened HttpOnly cookie.
func (a *Authenticator) setCookie(c *gin.Context, name, value string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, value, maxAge, "/", "", a.cookieSecure(c), true)
}

func (a *Authenticator) clearCookie(c *gin.Context, name string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, "", -1, "/", "", false, true)
}
