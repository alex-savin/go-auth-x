package authx

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Step-up (re-authentication) for sensitive actions. A consumer wraps a sensitive route with
// RequireStepUpHTTP(maxAge); if the user hasn't re-proven a factor within maxAge, the route returns
// 403 {"error":"reauth_required"} and the SPA prompts for POST /auth/reauth (password OR a 2FA code),
// which sets a short-lived signed step-up cookie bound to the session user.

const (
	stepUpCookie    = "sweep_stepup"
	stepUpCookieTTL = 30 * time.Minute // cookie lifetime; RequireStepUp enforces the actual freshness window
)

type stepUpClaims struct {
	jwt.RegisteredClaims
}

func (a *Authenticator) setStepUpCookie(c *reqCtx, sub string) {
	now := time.Now()
	tok, err := signJWT(a.cfg.SessionSecret, stepUpClaims{jwt.RegisteredClaims{
		Subject:   sub,
		Audience:  jwt.ClaimStrings{audStepUp},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(stepUpCookieTTL)),
	}})
	if err != nil {
		return
	}
	a.setCookie(c, stepUpCookie, tok, int(stepUpCookieTTL/time.Second))
}

// StepUpFresh reports whether the request carries a valid step-up proof for the CURRENT session user,
// issued within maxAge. (Bound to the session subject so a step-up from one account can't elevate
// another.)
func (a *Authenticator) StepUpFresh(r *http.Request, maxAge time.Duration) bool {
	sc, err := parseSession(a.cfg.SessionSecret, cookieValue(r, sessionCookie))
	if err != nil {
		return false
	}
	var claims stepUpClaims
	if parseJWT(a.cfg.SessionSecret, cookieValue(r, stepUpCookie), &claims, audStepUp) != nil {
		return false
	}
	if claims.Subject != sc.Subject || claims.IssuedAt == nil {
		return false
	}
	return time.Since(claims.IssuedAt.Time) <= maxAge
}

// RequireStepUpHTTP wraps a handler so it requires a re-authentication within maxAge. On a
// stale/absent step-up it responds 403 {"error":"reauth_required"} — the client prompts for
// POST /auth/reauth, then retries.
func (a *Authenticator) RequireStepUpHTTP(maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.StepUpFresh(r, maxAge) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "reauth_required"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReAuth (POST /auth/reauth, session-gated) re-verifies the signed-in user with a password OR a 2FA
// code, and on success sets the step-up cookie.
func (a *Authenticator) ReAuth(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	var body struct{ Password, Code string }
	_ = c.ShouldBindJSON(&body)

	ok := false
	if body.Password != "" {
		if hash, _, perr := a.creds.PasswordHash(au.ID); perr == nil {
			ok = bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) == nil
		}
	}
	if !ok && body.Code != "" && a.twoFactor != nil {
		if info, ierr := a.twoFactor.TOTP(au.ID); ierr == nil && info != nil && info.Enabled {
			ok = a.verifySecondFactor(au.ID, info, body.Code)
		}
	}
	if !ok {
		a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "reauth", "reauth", false, "")
		c.JSON(http.StatusForbidden, H{"error": "re-authentication failed"})
		return
	}
	a.setStepUpCookie(c, au.Sub)
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "reauth", "reauth", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}
