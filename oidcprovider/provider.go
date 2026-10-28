// Package oidcprovider makes an app that embeds go-auth-x an OAuth 2.1 / OpenID Connect provider:
// other programs — a satellite service, or an AI assistant's connector speaking the MCP
// authorization spec — can ask a signed-in user for access and receive tokens the app verifies.
//
// It is built on github.com/zitadel/oidc (PKCE, codes, token and refresh handling, signing,
// discovery) behind an authx-flavoured facade, and adds what MCP clients need: RFC 8414 metadata,
// dynamic client registration (RFC 7591), resource indicators (RFC 8707) binding tokens to the
// resource they are for, and rotating refresh tokens that end their grant when one is replayed.
//
// The user signs in with go-auth-x itself (the session cookie is the provider's login), and the
// consent screen is the app's: the provider sends the browser to Config.ConsentURL, the app shows
// the request (Pending) and records the user's decision (Approve or Deny). Access tokens are
// opaque; the app checks them with Verify. Mount Handler on the paths Patterns returns.
package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	authx "github.com/alex-savin/go-auth-x"
)

// Sessions is what the provider needs of the app's Authenticator.
type Sessions interface {
	SessionOf(r *http.Request) *authx.SessionClaims
	UserBySub(sub string) (*authx.AuthUser, error)
	ClientIP(r *http.Request) string
	CSRFValid(r *http.Request) bool
}

var _ Sessions = (*authx.Authenticator)(nil)

// Config configures a Provider. Issuer, Auth, Store and CryptoKey are required.
type Config struct {
	// Issuer is the provider's stable public URL, e.g. "https://tree.example.com". Discovery
	// documents are served under it (/.well-known/...), the endpoints under Issuer + Prefix.
	Issuer string
	// Prefix is the path the endpoints live under (default "/oauth").
	Prefix string
	// Auth is the app's sign-in: its session is the provider's login. An *authx.Authenticator
	// satisfies it; an app that rebuilds its Authenticator passes a forwarder to the current one.
	Auth Sessions
	// Store keeps clients, requests, grants, tokens and signing keys. Share it between replicas.
	Store authx.OAuthStore
	// CryptoKey (32 bytes) encrypts access tokens. Keep it secret and stable: changing it ends every
	// access token (refresh tokens keep working).
	CryptoKey []byte

	// Scopes are the scopes, beyond openid, profile, email and offline_access, clients may ask for.
	Scopes []string
	// DefaultScopes are asked for on behalf of a request that names none (MCP clients often don't).
	DefaultScopes []string
	// Resources are the resource indicators (RFC 8707) tokens may be bound to, e.g.
	// "https://tree.example.com/mcp". A request naming another is refused; a request naming none
	// is bound to the only one when there is exactly one.
	Resources []string

	// LoginURL is where a browser without a session signs in, coming back to returnTo (a path on
	// this site) afterwards. Default: "/welcome?next=" + returnTo.
	LoginURL func(returnTo string) string
	// ConsentURL is the app's consent screen for a request id. Nil approves every request as soon
	// as the user is signed in, with everything it asks — only for first-party clients.
	ConsentURL func(requestID string) string
	// Registration enables dynamic client registration at Prefix + "/register" (needed by most MCP
	// clients; anyone may register a client, but only a user's approval gives it access).
	Registration bool

	// AccessTokenTTL is an access token's life (default 1 hour).
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh token may go unused (default 30 days).
	RefreshTokenTTL time.Duration
	// UnusedClientTTL is how long a dynamically registered client that issued no token is kept
	// (default 30 days).
	UnusedClientTTL time.Duration

	// Claims adds claims to ID tokens and userinfo for the granted scopes (optional).
	Claims func(ctx context.Context, subject string, scopes []string) (map[string]any, error)
	// Logger receives the provider's warnings; nil uses slog.Default().
	Logger *slog.Logger
	// Insecure allows an http issuer and http redirect URIs (development only).
	Insecure bool
}

const (
	authRequestTTL = 10 * time.Minute // from /authorize to the code exchange
	codeTTL        = time.Minute      // from the code's issue to its exchange
	idTokenTTL     = time.Hour
)

// Provider is an embedded OAuth 2.1 / OIDC provider.
type Provider struct {
	cfg    Config
	op     *op.Provider
	store  *storage
	prefix string
	mux    *http.ServeMux
	reg    *limiter

	stop chan struct{}
	once sync.Once
}

// New builds the provider, creating a signing key on first use, and starts the clean-up of
// expired records (stopped by Close).
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Auth == nil || cfg.Store == nil {
		return nil, errors.New("oidcprovider: Auth and Store are required")
	}
	if len(cfg.CryptoKey) != 32 {
		return nil, errors.New("oidcprovider: CryptoKey must be 32 bytes")
	}
	iss, err := url.Parse(cfg.Issuer)
	if err != nil || iss.Host == "" || (iss.Scheme != "https" && !(cfg.Insecure && iss.Scheme == "http")) || iss.RawQuery != "" || iss.Fragment != "" {
		return nil, fmt.Errorf("oidcprovider: Issuer %q must be an https URL", cfg.Issuer)
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.Prefix == "" {
		cfg.Prefix = "/oauth"
	}
	cfg.Prefix = "/" + strings.Trim(cfg.Prefix, "/")
	if cfg.LoginURL == nil {
		cfg.LoginURL = func(returnTo string) string { return "/welcome?next=" + url.QueryEscape(returnTo) }
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if cfg.UnusedClientTTL <= 0 {
		cfg.UnusedClientTTL = 30 * 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	for i, r := range cfg.Resources {
		cfg.Resources[i] = normResource(r)
	}

	p := &Provider{cfg: cfg, prefix: cfg.Prefix, stop: make(chan struct{}), reg: newLimiter(20, time.Hour)}
	p.store = &storage{p: p, codes: map[string]time.Time{}}
	if err := p.store.loadKeys(); err != nil {
		return nil, err
	}

	var key [32]byte
	copy(key[:], cfg.CryptoKey)
	opCfg := &op.Config{
		CryptoKey:             key,
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       append([]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess}, cfg.Scopes...),
	}
	ep := func(s string) *op.Endpoint { e := op.NewEndpoint(p.prefix + s); return e }
	opts := []op.Option{
		op.WithCustomEndpoints(ep("/authorize"), ep("/token"), ep("/userinfo"), ep("/revoke"), ep("/end_session"), ep("/keys")),
		op.WithCustomIntrospectionEndpoint(ep("/introspect")),
		op.WithLogger(cfg.Logger),
	}
	if cfg.Insecure {
		opts = append(opts, op.WithAllowInsecure())
	}
	p.op, err = op.NewProvider(opCfg, p.store, op.StaticIssuer(cfg.Issuer), opts...)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(p.prefix+"/authorize", p.authorize)
	mux.HandleFunc(p.prefix+"/login", p.login)
	mux.HandleFunc(p.prefix+"/consent", p.consentJSON)
	if cfg.Registration {
		mux.HandleFunc(p.prefix+"/register", p.register)
	}
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/.well-known/oauth-authorization-server", p.discovery)
	mux.Handle(p.prefix+"/", p.op)
	p.mux = mux

	go p.gc()
	return p, nil
}

// Handler serves the provider: the endpoints under Prefix and the discovery documents.
func (p *Provider) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		p.mux.ServeHTTP(w, r)
	})
}

// Patterns are the paths to mount Handler on (net/http ServeMux patterns).
func (p *Provider) Patterns() []string {
	return []string{p.prefix + "/", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"}
}

// Issuer is the provider's issuer URL, for protected-resource metadata (RFC 9728).
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// Close stops the clean-up goroutine.
func (p *Provider) Close() { p.once.Do(func() { close(p.stop) }) }

func (p *Provider) gc() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			now := time.Now()
			if err := p.cfg.Store.DeleteExpiredOAuth(now, now.Add(-authRequestTTL), now.Add(-p.cfg.UnusedClientTTL)); err != nil {
				p.cfg.Logger.Warn("oidcprovider: clean-up failed", "err", err)
			}
			p.store.forgetCodes(now)
			p.reg.sweep(now)
		}
	}
}

// --- helpers ---

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// normResource drops a trailing slash (and fragment) so "https://x/mcp/" and "https://x/mcp" match.
func normResource(r string) string {
	r = strings.TrimSpace(r)
	if i := strings.IndexByte(r, '#'); i >= 0 {
		r = r[:i]
	}
	if u, err := url.Parse(r); err == nil && u.Path != "/" {
		return strings.TrimRight(r, "/")
	}
	return r
}

// resources checks a request's resource indicators against the configured ones.
func (p *Provider) resources(asked []string) ([]string, bool) {
	if len(asked) == 0 {
		if len(p.cfg.Resources) == 1 {
			return []string{p.cfg.Resources[0]}, true
		}
		return nil, true
	}
	var out []string
	for _, a := range asked {
		a = normResource(a)
		if !slices.Contains(p.cfg.Resources, a) {
			return nil, false
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, true
}

// limiter allows n events per key in each window (the registration endpoint, per address).
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string]*bucket
}

type bucket struct {
	start time.Time
	n     int
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, seen: map[string]*bucket{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.seen[key]
	if b == nil || now.Sub(b.start) >= l.window {
		b = &bucket{start: now}
		l.seen[key] = b
	}
	if b.n >= l.n {
		return false
	}
	b.n++
	return true
}

func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.seen {
		if now.Sub(b.start) >= l.window {
			delete(l.seen, k)
		}
	}
}
