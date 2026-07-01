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

func signJWT(secret []byte, claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// parseJWT verifies the HMAC signature (rejecting any other alg), requires the token's audience to
// match audience (so a token minted for one purpose can't be accepted for another), requires exp,
// and populates dest.
func parseJWT(secret []byte, token string, dest jwt.Claims, audience string) error {
	_, err := jwt.ParseWithClaims(token, dest, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithAudience(audience), jwt.WithExpirationRequired())
	return err
}

func mintSession(secret []byte, sub, email, name, role, idToken string, groups []string, now time.Time, ttl time.Duration) (string, error) {
	return signJWT(secret, SessionClaims{
		Email:   email,
		Name:    name,
		Groups:  groups,
		Role:    role,
		IDToken: idToken,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{audSession},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	})
}

func parseSession(secret []byte, token string) (*SessionClaims, error) {
	if token == "" {
		return nil, errors.New("no session cookie")
	}
	var c SessionClaims
	if err := parseJWT(secret, token, &c, audSession); err != nil {
		return nil, err
	}
	if c.Subject == "" {
		return nil, errors.New("session missing subject")
	}
	return &c, nil
}

func mintFlow(secret []byte, fc flowClaims, now time.Time) (string, error) {
	fc.Audience = jwt.ClaimStrings{audFlow}
	fc.IssuedAt = jwt.NewNumericDate(now)
	fc.ExpiresAt = jwt.NewNumericDate(now.Add(flowTTL))
	return signJWT(secret, fc)
}

func parseFlow(secret []byte, token string) (*flowClaims, error) {
	if token == "" {
		return nil, errors.New("no login-flow cookie")
	}
	var c flowClaims
	if err := parseJWT(secret, token, &c, audFlow); err != nil {
		return nil, err
	}
	return &c, nil
}
