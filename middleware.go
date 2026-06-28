package authx

import (
	"net/http"
	"os"
	"strings"
)

const (
	sessionCookie = "sweep_session"
	flowCookie    = "sweep_oidc_flow"
)

// enforcing reports whether the request gate is active. Unlike Enabled() (OIDC only), this is true
// whenever ANY auth method is live — OIDC OR in-app local auth — so a password/passkey-only
// deployment (no OIDC issuer) is still gated instead of silently wide open.
func (a *Authenticator) enforcing() bool {
	return a != nil && (a.enabled || a.LocalEnabled())
}

// TrustedProxies returns the proxy IPs/CIDRs to trust when extracting the client IP from
// X-Forwarded-For, read from TRUSTED_PROXIES (comma-separated) or a private-range default that
// matches the usual reverse-proxy-on-a-private-network deployment. Without it XFF is honored from
// any peer, letting a client spoof it to defeat per-IP rate limits.
func TrustedProxies() []string {
	if v := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES")); v != "" {
		return splitCSV(v)
	}
	return []string{"127.0.0.1/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
}

// isPublicPath lists routes reachable without a session: the auth flow itself, static assets, the
// container healthcheck, and the consuming app's login pages. (Consumer-configurable matching is a
// roadmap item; today these defaults cover the reference UI.)
func isPublicPath(p string) bool {
	if strings.HasPrefix(p, "/_next/") || strings.HasPrefix(p, "/auth/") {
		return true
	}
	switch p {
	case "/api/health", "/favicon.ico", "/signup", "/welcome", "/restore",
		"/login", "/register", "/recover", "/reset", "/verify":
		return true
	}
	return false
}

// sessionFrom returns the session GateHTTP attached to the request context (the gating path).
func sessionFrom(c *reqCtx) *SessionClaims {
	if sc, ok := c.Request.Context().Value(sessionCtxKey).(*SessionClaims); ok {
		return sc
	}
	return nil
}

// sessionOf resolves the session straight from the cookie — for /auth handlers (admin API, account
// endpoints) that self-gate rather than sitting behind GateHTTP.
func (a *Authenticator) sessionOf(c *reqCtx) *SessionClaims {
	sc, err := parseSession(a.cfg.SessionSecret, cookieValue(c.Request, sessionCookie))
	if err != nil {
		return nil
	}
	return sc
}

// setCookie writes a hardened HttpOnly cookie.
func (a *Authenticator) setCookie(c *reqCtx, name, value string, maxAge int) {
	http.SetCookie(c.w, &http.Cookie{
		Name: name, Value: value, MaxAge: maxAge, Path: "/",
		Secure: a.cookieSecureHTTP(c.Request), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearCookie(c *reqCtx, name string) {
	http.SetCookie(c.w, &http.Cookie{Name: name, Value: "", MaxAge: -1, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
