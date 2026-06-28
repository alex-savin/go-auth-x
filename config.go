// Package auth adds optional OIDC authorization in front of the
// whole service. It runs a backend-for-frontend Authorization Code + PKCE flow and
// issues a signed HttpOnly session cookie — the SPA never handles tokens. Auth is
// opt-in: with no OIDC_ISSUER/OIDC_CLIENT_ID configured everything no-ops and the
// service behaves as before (open), so the demo and tests are unaffected.
package authx

import (
	"os"
	"strings"
)

// Config is read from the environment at boot. Auth turns on only when an issuer
// and client id are present.
type Config struct {
	Issuer        string   // OIDC_ISSUER, e.g. https://id.example.com
	ClientID      string   // OIDC_CLIENT_ID
	ClientSecret  string   // OIDC_CLIENT_SECRET (confidential client)
	RedirectURL   string   // OIDC_REDIRECT_URL, e.g. https://app.example.com/auth/callback
	AllowedGroups []string // OIDC_ALLOWED_GROUPS (comma-sep); empty = any authenticated user
	SessionSecret []byte   // SESSION_SECRET — HMAC key for the session/flow cookies
	CookieSecure  bool     // COOKIE_SECURE — force the Secure flag (also auto-on under TLS)
	// AppURL (APP_URL) is the public origin of the app, used to build email links and
	// post-login redirects (e.g. https://trader.savin.nyc). Falls back to RedirectURL's origin.
	AppURL string
	// OwnerEmail (OWNER_EMAIL) is exempt from hard per-account lockout so the operator can't
	// be locked out mid-migration (recovery via email link stays open regardless).
	OwnerEmail string
	// OIDCAssumeVerified (OIDC_ASSUME_VERIFIED) trusts the issuer's email as verified even when the
	// id_token omits an email_verified claim. Leave false (default) to require the claim — the
	// correct posture for multi-IdP setups; set true only for a single, fully-trusted issuer that
	// doesn't emit the claim.
	OIDCAssumeVerified bool
	// PublicPath, if set, is consulted (in addition to the always-public /auth, /_next, health
	// routes) to decide which paths the gate lets through unauthenticated — e.g. your SPA's login
	// pages. nil = the built-in reference defaults (/login, /register, /welcome, …).
	PublicPath func(path string) bool
	// Social login (OAuth). Each provider turns on only when its client id + secret are set.
	// Callback URLs are AppURL + /auth/social/{google,github}/callback (register them upstream).
	GoogleClientID     string // GOOGLE_CLIENT_ID
	GoogleClientSecret string // GOOGLE_CLIENT_SECRET
	GitHubClientID     string // GITHUB_CLIENT_ID
	GitHubClientSecret string // GITHUB_CLIENT_SECRET
}

// ConfigFromEnv loads the OIDC configuration from the environment.
func ConfigFromEnv() Config {
	return Config{
		Issuer:        strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/"),
		ClientID:      os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:   os.Getenv("OIDC_REDIRECT_URL"),
		AllowedGroups: splitCSV(os.Getenv("OIDC_ALLOWED_GROUPS")),
		SessionSecret: []byte(os.Getenv("SESSION_SECRET")),
		CookieSecure:  os.Getenv("COOKIE_SECURE") == "true",
		AppURL:        strings.TrimRight(os.Getenv("APP_URL"), "/"),
		OwnerEmail:    strings.ToLower(strings.TrimSpace(os.Getenv("OWNER_EMAIL"))),

		OIDCAssumeVerified: os.Getenv("OIDC_ASSUME_VERIFIED") == "true",

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	}
}

// Enabled reports whether auth should be enforced. The session secret is required
// too — without it the signed cookies would be unsafe.
func (c Config) Enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && len(c.SessionSecret) > 0
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
