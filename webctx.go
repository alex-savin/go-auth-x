package authx

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// maxRequestBody caps JSON request bodies so an unbounded payload can't exhaust memory.
const maxRequestBody = 1 << 20 // 1 MiB

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

func (c *reqCtx) JSON(code int, obj any)    { writeJSON(c.w, code, obj) }
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
func (c *reqCtx) ShouldBindJSON(v any) error {
	return json.NewDecoder(http.MaxBytesReader(c.w, c.Request.Body, maxRequestBody)).Decode(v)
}
func (c *reqCtx) Redirect(code int, url string) { http.Redirect(c.w, c.Request, url, code) }
func (c *reqCtx) ClientIP() string              { return c.a.clientIP(c.Request) }

// rateAfterSeconds is the Retry-After hint (seconds) returned with a 429 throttle response.
const rateAfterSeconds = 60

// tooMany writes a 429 with a Retry-After header so clients (and well-behaved bots) back off instead
// of hammering. Used for every auth rate-limit / lockout throttle.
func (c *reqCtx) tooMany(msg string) {
	c.w.Header().Set("Retry-After", strconv.Itoa(rateAfterSeconds))
	c.JSON(http.StatusTooManyRequests, H{"error": msg})
}

// rateIP returns the client IP normalized for rate-limit KEYS: an IPv6 address collapses to its /64
// prefix (a single actor is typically handed a whole /64, so per-address limits are trivially dodged
// by rotating within it), while IPv4 is unchanged. Not for audit/display — use ClientIP() there.
func (c *reqCtx) rateIP() string { return maskIPForRateLimit(c.ClientIP()) }

func maskIPForRateLimit(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if parsed.To4() != nil {
		return ip // IPv4 (incl. IPv4-mapped): key on the exact address
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

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

// trustedProxyNets caches the parsed trusted-proxy ranges. TrustedProxies() reads the env and parses
// CIDRs on every call; trustedProxy is on the per-request client-IP path, so parse once.
var (
	trustedProxyOnce  sync.Once
	trustedProxyNets  []*net.IPNet
	trustedProxyExact []net.IP
)

func loadTrustedProxies() {
	for _, cidr := range TrustedProxies() {
		if !strings.Contains(cidr, "/") {
			if ip := net.ParseIP(cidr); ip != nil {
				trustedProxyExact = append(trustedProxyExact, ip)
			}
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			trustedProxyNets = append(trustedProxyNets, n)
		}
	}
}

// trustedProxy reports whether ip falls within the configured trusted-proxy ranges.
func trustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	trustedProxyOnce.Do(loadTrustedProxies)
	for _, exact := range trustedProxyExact {
		if parsed.Equal(exact) {
			return true
		}
	}
	for _, n := range trustedProxyNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
