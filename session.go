package authx

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	sessionTTL  = 12 * time.Hour      // default session lifetime
	rememberTTL = 30 * 24 * time.Hour // "remember me" session lifetime
	flowTTL     = 10 * time.Minute
)

// Per-purpose token audiences. All our cookies are HS256-signed with the same SESSION_SECRET, so we
// stamp a distinct `aud` on each and require it on parse — otherwise e.g. a 2FA-pending token (first
// factor only) could be replayed in the session-cookie slot and bypass the second factor.
const (
	audSession  = "authx:session"
	audFlow     = "authx:oauth-flow"
	audWebauthn = "authx:webauthn-flow"
	audPending  = "authx:2fa-pending"
	audStepUp   = "authx:stepup"
)

// SessionClaims is the signed session-cookie payload — the authenticated identity.
type SessionClaims struct {
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Role    string   `json:"role,omitempty"` // optional role from an Authorizer
	IDToken string   `json:"idt,omitempty"`  // raw OIDC id_token — used as id_token_hint at RP-initiated logout
	// SID is a random per-session id, present only when an optional SessionStore is wired. It lets the
	// gate consult server-side revocation (sign-out-everywhere, list/revoke devices). Empty = the
	// default stateless behavior (no server-side session record).
	SID string `json:"sid,omitempty"`
	// ImpersonatedBy is the admin subject when this session was minted by admin impersonation. Surfaced
	// at /auth/me so the app can show a banner, and refused by adminGuard so an impersonated session
	// can't perform further admin actions.
	ImpersonatedBy string `json:"imp,omitempty"`
	jwt.RegisteredClaims
}

// flowClaims is the short-lived cookie carrying in-flight OIDC login state (CSRF
// state, nonce, PKCE verifier, and the post-login redirect target).
type flowClaims struct {
	State    string `json:"st"`
	Nonce    string `json:"no"`
	Verifier string `json:"ve"`
	Next     string `json:"nx"`
	jwt.RegisteredClaims
}

// minSessionSecret is the floor for the HMAC key that signs every cookie. jwt's HS256 SignedString
// accepts an empty/short key without error, so without this guard a misconfigured deployment (local
// auth with SESSION_SECRET unset) would silently mint cookies forgeable by anyone. Fail closed.
const minSessionSecret = 32

// verifySecrets returns the primary signing secret followed by any PreviousSessionSecrets, so a
// rotated SESSION_SECRET can still verify cookies signed by a prior key during the rollover window.
// Signing always uses the primary (see signingSecret); only verification consults the whole list.
func (a *Authenticator) verifySecrets() [][]byte {
	out := make([][]byte, 0, 1+len(a.cfg.PreviousSessionSecrets))
	// Only keys of the required strength may verify — otherwise a deployment that booted with an
	// empty/short SESSION_SECRET (local enabled, no OIDC) would ACCEPT a cookie forged with that weak
	// key. Signing already fails closed on a short key; verification must too (symmetric fail-closed).
	if len(a.cfg.SessionSecret) >= minSessionSecret {
		out = append(out, a.cfg.SessionSecret)
	}
	for _, s := range a.cfg.PreviousSessionSecrets {
		if len(s) >= minSessionSecret {
			out = append(out, s)
		}
	}
	return out
}

func signJWT(secret []byte, claims jwt.Claims) (string, error) {
	if len(secret) < minSessionSecret {
		return "", errors.New("authx: refusing to sign a cookie — SESSION_SECRET must be at least 32 bytes")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// parseJWTMulti verifies the token against each secret in turn (primary then any previous keys),
// accepting it on the first that validates. Signature/audience/exp are enforced exactly as the
// single-key path; the which-key-matched timing signal is useless to an attacker (each per-key HMAC
// compare is itself constant-time).
func parseJWTMulti(secrets [][]byte, token string, dest jwt.Claims, audience string) error {
	var lastErr error = errors.New("authx: no session secret configured")
	for _, secret := range secrets {
		if err := parseJWT(secret, token, dest, audience); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// parseJWT verifies the HMAC signature (rejecting any other alg), requires the token's audience to
// match audience (so a token minted for one purpose can't be accepted for another), requires exp,
// and populates dest.
func parseJWT(secret []byte, token string, dest jwt.Claims, audience string) error {
	// Never verify against an under-strength key (defense-in-depth alongside verifySecrets): a short/empty
	// HMAC key is forgeable, so a cookie signed with one must be rejected, not accepted.
	if len(secret) < minSessionSecret {
		return errors.New("authx: refusing to verify a cookie with a secret shorter than the minimum")
	}
	_, err := jwt.ParseWithClaims(token, dest, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	return err
}

// mintSession mints a session cookie with no SID (the stateless default). mintSessionWith is used when
// a SID (session-store) or impersonation marker must be embedded.
func mintSession(secret []byte, sub, email, name, role, idToken string, groups []string, now time.Time, ttl time.Duration) (string, error) {
	return mintSessionWith(secret, SessionClaims{Email: email, Name: name, Groups: groups, Role: role, IDToken: idToken}, sub, now, ttl)
}

// mintSessionWith signs a session cookie from a caller-provided base (which may carry SID / IDToken /
// ImpersonatedBy), stamping the subject, audience, and validity window.
func mintSessionWith(secret []byte, base SessionClaims, sub string, now time.Time, ttl time.Duration) (string, error) {
	base.RegisteredClaims = jwt.RegisteredClaims{
		Subject:   sub,
		Audience:  jwt.ClaimStrings{audSession},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	return signJWT(secret, base)
}

// parseSessionMulti parses a session cookie, trying each verify secret (primary + previous).
func parseSessionMulti(secrets [][]byte, token string) (*SessionClaims, error) {
	if token == "" {
		return nil, errors.New("no session cookie")
	}
	var c SessionClaims
	if err := parseJWTMulti(secrets, token, &c, audSession); err != nil {
		return nil, err
	}
	if c.Subject == "" {
		return nil, errors.New("session missing subject")
	}
	return &c, nil
}

func parseSession(secret []byte, token string) (*SessionClaims, error) {
	return parseSessionMulti([][]byte{secret}, token)
}

func mintFlow(secret []byte, fc flowClaims, now time.Time) (string, error) {
	fc.Audience = jwt.ClaimStrings{audFlow}
	fc.IssuedAt = jwt.NewNumericDate(now)
	fc.ExpiresAt = jwt.NewNumericDate(now.Add(flowTTL))
	return signJWT(secret, fc)
}

func parseFlowMulti(secrets [][]byte, token string) (*flowClaims, error) {
	if token == "" {
		return nil, errors.New("no login-flow cookie")
	}
	var c flowClaims
	if err := parseJWTMulti(secrets, token, &c, audFlow); err != nil {
		return nil, err
	}
	return &c, nil
}

func parseFlow(secret []byte, token string) (*flowClaims, error) {
	return parseFlowMulti([][]byte{secret}, token)
}
