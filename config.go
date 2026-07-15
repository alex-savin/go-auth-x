// Package authx is a self-contained authentication library for Go web apps: passwords, passkeys
// (WebAuthn), email magic-links, OIDC, social login, and 2FA behind one signed HttpOnly session
// cookie — the SPA never handles tokens. It runs a backend-for-frontend Authorization Code + PKCE
// flow and is opt-in: with no OIDC_ISSUER/OIDC_CLIENT_ID and no local methods enabled everything
// no-ops and the service behaves as before (open), so the demo and tests are unaffected.
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
	// PreviousSessionSecrets are retired signing keys still accepted for VERIFICATION (never signing),
	// so SESSION_SECRET can be rotated without logging every user out at once. Populate from
	// SESSION_SECRET_PREVIOUS (comma-separated) or programmatically; keep an old key only for one
	// session TTL after rotation, then drop it (each entry widens the trusted-signer set). Each must
	// also be at least 32 bytes.
	PreviousSessionSecrets [][]byte
	CookieSecure           bool // COOKIE_SECURE — force the Secure flag (also auto-on under TLS)
	// TrustedOrigins is an optional allow-list of exact origins (scheme://host[:port]) accepted on
	// state-changing requests as defense-in-depth ON TOP OF the double-submit CSRF token. AppURL's
	// origin is always allowed. Empty (and an absent Origin/Referer) fails open — the token remains
	// the primary check — so this never rejects a legitimate same-origin request.
	TrustedOrigins []string
	// BreachCheckHIBP (HIBP_BREACH_CHECK=true) wires the default Have I Been Pwned k-anonymity password
	// checker at boot. It can also be set programmatically via SetBreachChecker with a custom checker.
	BreachCheckHIBP bool
	// AppURL (APP_URL) is the public origin of the app, used to build email links and
	// post-login redirects (e.g. https://trader.savin.nyc). Falls back to RedirectURL's origin.
	AppURL string
	// OwnerEmail (OWNER_EMAIL) is exempt from hard per-account lockout so the operator can't
	// be locked out mid-migration (recovery via email link stays open regardless).
	OwnerEmail string
	// BrandName (BRAND_NAME) labels the auth emails and is the default WebAuthn relying-party
	// display name. Falls back to "go-auth-x" when unset.
	BrandName string
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
	// Callback URLs are AppURL + /auth/social/<provider>/callback — one per enabled provider
	// (google, github, facebook, apple, microsoft, discord, and any SocialOIDC slug) — register
	// each upstream.
	GoogleClientID       string // GOOGLE_CLIENT_ID
	GoogleClientSecret   string // GOOGLE_CLIENT_SECRET
	GitHubClientID       string // GITHUB_CLIENT_ID
	GitHubClientSecret   string // GITHUB_CLIENT_SECRET
	FacebookClientID     string // FACEBOOK_CLIENT_ID
	FacebookClientSecret string // FACEBOOK_CLIENT_SECRET
	// Sign in with Apple. The "client secret" is an ES256 JWT the library signs from your private
	// key, so Apple needs four values: the Services ID (client id), your Team ID, the Key ID, and the
	// .p8 EC private key (PEM; literal or with \n-escaped newlines). Apple posts its callback
	// (form_post), so its flow cookie is set SameSite=None — HTTPS is required.
	AppleClientID   string // APPLE_CLIENT_ID (Services ID)
	AppleTeamID     string // APPLE_TEAM_ID
	AppleKeyID      string // APPLE_KEY_ID
	ApplePrivateKey string // APPLE_PRIVATE_KEY (.p8 PEM)

	// Microsoft / Entra ID (OIDC). Tenant defaults to "common" (any work/school or personal Microsoft
	// account) — a MULTI-TENANT endpoint whose token email is NOT trustworthy: any Entra tenant can mint
	// a token asserting any address (nOAuth). Set MICROSOFT_TENANT to a single tenant GUID / verified
	// custom domain to restrict sign-in to that organization, which is the ONLY configuration in which the
	// token email is trusted. With a multi-tenant endpoint the email is treated as unverified, so Entra's
	// (which omits email_verified) sign-ins are refused until a tenant is pinned. MicrosoftStrictEmailVerified
	// additionally requires an explicit email_verified even for a pinned single tenant.
	MicrosoftClientID            string // MICROSOFT_CLIENT_ID
	MicrosoftClientSecret        string // MICROSOFT_CLIENT_SECRET
	MicrosoftTenant              string // MICROSOFT_TENANT (default "common" — pin a single tenant to enable email sign-in)
	MicrosoftStrictEmailVerified bool   // MICROSOFT_STRICT_EMAIL_VERIFIED

	// Discord (OAuth2 + REST; requires a verified email).
	DiscordClientID     string // DISCORD_CLIENT_ID
	DiscordClientSecret string // DISCORD_CLIENT_SECRET

	// SocialOIDC registers arbitrary standards-compliant OIDC identity providers as social logins
	// (GitLab, Okta, Auth0, Keycloak, …), each mounted at /auth/social/<Name>/{login,callback}.
	// Programmatic only (set on the Config) — there is no env form.
	SocialOIDC []SocialOIDCProvider
}

// SocialOIDCProvider registers any OIDC-compliant identity provider as a social login. Discovery
// uses <Issuer>/.well-known/openid-configuration; sign-in follows the same Authorization Code +
// PKCE + nonce + azp + email_verified path as Google.
type SocialOIDCProvider struct {
	Name         string   // URL slug (lowercased), e.g. "gitlab", "okta", "auth0"
	Issuer       string   // OIDC issuer URL
	ClientID     string   // OAuth client id
	ClientSecret string   // OAuth client secret (confidential client)
	Scopes       []string // optional; defaults to openid, email, profile
	// AssumeVerified trusts the token's email when the provider omits email_verified (e.g. a
	// tenant that owns its addresses). Off by default — an absent/false email_verified is refused.
	AssumeVerified bool
}

// ConfigFromEnv loads the OIDC configuration from the environment.
func ConfigFromEnv() Config {
	return Config{
		Issuer:                 strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/"),
		ClientID:               os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:           os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:            os.Getenv("OIDC_REDIRECT_URL"),
		AllowedGroups:          splitCSV(os.Getenv("OIDC_ALLOWED_GROUPS")),
		SessionSecret:          []byte(os.Getenv("SESSION_SECRET")),
		PreviousSessionSecrets: envSecrets("SESSION_SECRET_PREVIOUS"),
		CookieSecure:           os.Getenv("COOKIE_SECURE") == "true",
		TrustedOrigins:         splitCSV(os.Getenv("TRUSTED_ORIGINS")),
		AppURL:                 strings.TrimRight(os.Getenv("APP_URL"), "/"),
		OwnerEmail:             strings.ToLower(strings.TrimSpace(os.Getenv("OWNER_EMAIL"))),
		BrandName:              strings.TrimSpace(os.Getenv("BRAND_NAME")),

		OIDCAssumeVerified: os.Getenv("OIDC_ASSUME_VERIFIED") == "true",
		BreachCheckHIBP:    os.Getenv("HIBP_BREACH_CHECK") == "true",

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),

		FacebookClientID:     os.Getenv("FACEBOOK_CLIENT_ID"),
		FacebookClientSecret: os.Getenv("FACEBOOK_CLIENT_SECRET"),

		AppleClientID:   os.Getenv("APPLE_CLIENT_ID"),
		AppleTeamID:     os.Getenv("APPLE_TEAM_ID"),
		AppleKeyID:      os.Getenv("APPLE_KEY_ID"),
		ApplePrivateKey: os.Getenv("APPLE_PRIVATE_KEY"),

		MicrosoftClientID:            os.Getenv("MICROSOFT_CLIENT_ID"),
		MicrosoftClientSecret:        os.Getenv("MICROSOFT_CLIENT_SECRET"),
		MicrosoftTenant:              os.Getenv("MICROSOFT_TENANT"),
		MicrosoftStrictEmailVerified: os.Getenv("MICROSOFT_STRICT_EMAIL_VERIFIED") == "true",

		DiscordClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		DiscordClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
	}
}

// Enabled reports whether auth should be enforced. The session secret is required
// too — without it the signed cookies would be unsafe.
func (c Config) Enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && len(c.SessionSecret) > 0
}

// envSecrets reads a comma-separated env var into a slice of byte keys (retired signing secrets).
func envSecrets(name string) [][]byte {
	parts := splitCSV(os.Getenv(name))
	if len(parts) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		out = append(out, []byte(p))
	}
	return out
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
