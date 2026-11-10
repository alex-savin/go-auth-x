package authx

import (
	"net/http"
	"os"
	"path"
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
	// Social login mints sessions too, so a social-only deployment (no OIDC issuer, no SetLocalEnabled)
	// must still gate — otherwise GateHTTP/CSRFHTTP would no-op while login quietly issues cookies.
	return a != nil && (a.enabled || a.LocalEnabled() || a.anySocialConfigured())
}

// TrustedProxies returns the proxy IPs/CIDRs to trust when extracting the client IP from
// X-Forwarded-For, read from TRUSTED_PROXIES (comma-separated) or a private-range default (IPv4 and
// IPv6) that matches the usual reverse-proxy-on-a-private-network deployment. The default trusts
// EVERY peer with a private address: where clients can reach the app from one without passing a
// proxy that rewrites the header (an intranet, a load balancer that keeps the client's address, a
// published container port), they choose their own IP — and with it their per-IP rate limit and the
// address in the audit log. Set TRUSTED_PROXIES to the proxy's own address there.
func TrustedProxies() []string {
	if v := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES")); v != "" {
		return splitCSV(v)
	}
	return []string{"127.0.0.1/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}
}

// publicPath reports routes reachable without a session: the auth flow itself, static assets, the
// container healthcheck — plus the consuming app's login pages, via Config.PublicPath (or the
// built-in reference defaults when that's nil).
func (a *Authenticator) publicPath(p string) bool {
	// Decide on the path the handler will serve: "/auth/../secret" is not under /auth/ (a handler
	// that cleans paths itself, like http.FileServer, serves /secret).
	p = path.Clean("/" + p)
	// The library's own surface is ALWAYS public, regardless of Config.PublicPath.
	if strings.HasPrefix(p, "/_next/") || strings.HasPrefix(p, "/auth/") || p == "/api/health" || p == "/favicon.ico" {
		return true
	}
	// Consumer-supplied matcher takes over the app-route decision when set.
	if a.cfg.PublicPath != nil {
		return a.cfg.PublicPath(p)
	}
	// Built-in reference-UI public routes (used only when no matcher is configured).
	switch p {
	case "/signup", "/welcome", "/restore", "/login", "/register", "/recover", "/reset", "/verify":
		return true
	}
	return false
}

// sessionOf resolves the session straight from the cookie — for /auth handlers (admin API, account
// endpoints) that self-gate rather than sitting behind GateHTTP.
func (a *Authenticator) sessionOf(c *reqCtx) *SessionClaims {
	sc, err := parseSessionMulti(a.verifySecrets(), a.cookieValue(c.Request, sessionCookie))
	if err != nil {
		return nil
	}
	if a.sessionRevoked(sc) {
		return nil
	}
	return sc
}

// setCookie writes a hardened HttpOnly cookie.
func (a *Authenticator) setCookie(c *reqCtx, name, value string, maxAge int) {
	http.SetCookie(c.w, &http.Cookie{
		Name: a.cookieName(name), Value: value, MaxAge: maxAge, Path: "/",
		Secure: a.cookieSecureHTTP(c.Request), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) clearCookie(c *reqCtx, name string) {
	// Secure as it was set: a browser takes a __Host- cookie's removal, like the cookie, only so.
	http.SetCookie(c.w, &http.Cookie{
		Name: a.cookieName(name), Value: "", MaxAge: -1, Path: "/",
		Secure: a.cookieSecureHTTP(c.Request), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}
