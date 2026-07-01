package authx

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/oauth2"
)

// Identity is the authenticated identity handed to an Authorizer after login.
type Identity struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// EmailVerified reports whether THIS login proved the email — the OIDC email_verified claim,
	// a provider-verified social email, or a redeemed in-app token. The reference Authorizer feeds
	// it to the safe account-linking rule (only a proven email may reclaim/adopt another row).
	EmailVerified bool
}

// Authorizer is an optional post-login hook (e.g. multi-tenant provisioning). It may
// run side effects (create the user's account, accept invites) and returns the role to
// embed in the session, or ErrAccessDenied to refuse the login.
type Authorizer interface {
	Authorize(ctx context.Context, id Identity) (role string, err error)
}

// ErrAccessDenied refuses a login from an Authorizer.
var ErrAccessDenied = errors.New("access denied")

// Authenticator holds the OIDC client wiring. When auth is disabled it is a valid
// no-op value (Enabled() == false) so callers never special-case nil.
type Authenticator struct {
	cfg      Config
	enabled  bool
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	// endSession is the issuer's RP-initiated logout endpoint, if advertised.
	endSession string
	// authorizer, if set, runs after token verification (multi-tenant provisioning).
	authorizer Authorizer
	// creds backs the in-app auth methods (password/passkey/email/social); nil = OIDC-only.
	creds CredentialStore
	// email sends the in-app auth mails (magic-link/verify/reset); nil = email methods off.
	email Mailer
	// localEnabled mirrors AUTH_LOCAL: in-app methods are wired only when true.
	localEnabled bool
	// Rate limiters for the local auth endpoints (per-IP + per-account); nil until enabled.
	// RateLimiter so consumers can swap in a shared-store backend via SetRateLimiters.
	ipLimiter   RateLimiter
	acctLimiter RateLimiter
	// wauthn is the WebAuthn relying-party instance for passkeys; nil until configured.
	wauthn *webauthn.WebAuthn
	// Social login OAuth (nil until the provider's client id + secret are set).
	googleOAuth, githubOAuth, facebookOAuth, appleOAuth *oauth2.Config
	googleVerifier, appleVerifier                       *oidc.IDTokenVerifier
	appleKey                                            *ecdsa.PrivateKey // parsed .p8, signs Apple's client-secret JWT
	// dir backs groups / API keys / admin REST (optional; nil = those features off).
	dir DirectoryStore
	// twoFactor backs optional TOTP 2FA + recovery codes (nil = 2FA off).
	twoFactor TwoFactorStore
}

// SetAuthorizer installs an optional post-login authorization hook.
func (a *Authenticator) SetAuthorizer(z Authorizer) { a.authorizer = z }

// New builds the Authenticator. If auth is not configured it returns a disabled
// (no-op) instance. If it IS configured it performs OIDC discovery against the
// issuer and fails on error — we'd rather refuse to boot than run unprotected when
// auth was intended (fail closed).
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	// Fail closed: the signed session/flow/CSRF cookies need a strong HMAC key. Whenever auth will
	// mint cookies — OIDC is configured, or a secret was supplied for local/social methods — require
	// SESSION_SECRET to be at least 32 bytes. A short key would silently weaken every signed cookie.
	if (cfg.Issuer != "" && cfg.ClientID != "") || len(cfg.SessionSecret) > 0 {
		if len(cfg.SessionSecret) < 32 {
			return nil, fmt.Errorf("authx: SESSION_SECRET must be at least 32 bytes (got %d)", len(cfg.SessionSecret))
		}
	}
	a := &Authenticator{cfg: cfg}
	if cfg.Enabled() {
		provider, err := oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, err
		}
		var meta struct {
			EndSessionEndpoint string `json:"end_session_endpoint"`
		}
		_ = provider.Claims(&meta)
		a.enabled = true
		a.provider = provider
		a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
		a.oauth = oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		}
		a.endSession = meta.EndSessionEndpoint
	}
	// Social providers are independent of the primary OIDC issuer (best-effort; a provider
	// stays off if its discovery fails or its credentials are unset).
	a.enableSocial(ctx)
	return a, nil
}

// Enabled reports whether auth is enforced.
func (a *Authenticator) Enabled() bool { return a != nil && a.enabled }

// groupAllowed enforces OIDC_ALLOWED_GROUPS. Empty config = any authenticated user.
func (a *Authenticator) groupAllowed(groups []string) bool {
	if len(a.cfg.AllowedGroups) == 0 {
		return true
	}
	have := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		have[g] = struct{}{}
	}
	for _, allowed := range a.cfg.AllowedGroups {
		if _, ok := have[allowed]; ok {
			return true
		}
	}
	return false
}
