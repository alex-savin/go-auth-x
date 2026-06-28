package authx

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// H is a generic JSON object for handler responses (mirrors gin.H, minus the framework).
type H = map[string]any

// reqCtx is a tiny request/response context that replaces *gin.Context so the handlers carry no
// framework dependency. Its method names mirror the subset of gin the handlers used, which keeps
// the handler bodies unchanged after the migration to net/http.
type reqCtx struct {
	Request *http.Request
	w       http.ResponseWriter
	a       *Authenticator
}

func (a *Authenticator) newCtx(w http.ResponseWriter, r *http.Request) *reqCtx {
	return &reqCtx{Request: r, w: w, a: a}
}

// wrap adapts an authx handler to a standard net/http handler.
func (a *Authenticator) wrap(h func(*reqCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { h(a.newCtx(w, r)) }
}

func (c *reqCtx) JSON(code int, obj any)                { writeJSON(c.w, code, obj) }
func (c *reqCtx) AbortWithStatusJSON(code int, obj any) { writeJSON(c.w, code, obj) }
func (c *reqCtx) String(code int, format string, a ...any) {
	c.w.WriteHeader(code)
	fmt.Fprintf(c.w, format, a...)
}
func (c *reqCtx) Query(k string) string     { return c.Request.URL.Query().Get(k) }
func (c *reqCtx) Param(k string) string     { return c.Request.PathValue(k) }
func (c *reqCtx) GetHeader(k string) string { return c.Request.Header.Get(k) }
func (c *reqCtx) Cookie(name string) (string, error) {
	ck, err := c.Request.Cookie(name)
	if err != nil {
		return "", err
	}
	return ck.Value, nil
}
func (c *reqCtx) ShouldBindJSON(v any) error    { return json.NewDecoder(c.Request.Body).Decode(v) }
func (c *reqCtx) Redirect(code int, url string) { http.Redirect(c.w, c.Request, url, code) }
func (c *reqCtx) ClientIP() string              { return c.a.clientIP(c.Request) }

// clientIP extracts the client IP, honoring X-Forwarded-For ONLY when the direct peer is a trusted
// proxy (so XFF can't be spoofed) — the behavior gin's SetTrustedProxies provided.
func (a *Authenticator) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !trustedProxy(host) {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if ip := strings.TrimSpace(parts[i]); ip != "" && !trustedProxy(ip) {
				return ip
			}
		}
	}
	return host
}

// trustedProxy reports whether ip falls within the configured trusted-proxy ranges.
func trustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range TrustedProxies() {
		if !strings.Contains(cidr, "/") {
			if parsed.Equal(net.ParseIP(cidr)) {
				return true
			}
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}
