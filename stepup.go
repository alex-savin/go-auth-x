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

// The factor a step-up was made with. A password re-proves what a stolen password already proves; a
// TOTP or recovery code proves the second factor.
const (
	stepUpPassword = "pwd"
	stepUpCode     = "otp"
)

type stepUpClaims struct {
	Factor string `json:"amr,omitempty"`
	jwt.RegisteredClaims
}

func (a *Authenticator) setStepUpCookie(c *reqCtx, sub, factor string) {
	now := time.Now()
	tok, err := signJWT(a.cfg.SessionSecret, stepUpClaims{Factor: factor, RegisteredClaims: jwt.RegisteredClaims{
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
	return a.stepUpFresh(r, maxAge, "")
}

// stepUpFresh is StepUpFresh, and with a factor, only for a step-up made with that factor.
func (a *Authenticator) stepUpFresh(r *http.Request, maxAge time.Duration, factor string) bool {
	sc, err := parseSessionMulti(a.verifySecrets(), a.cookieValue(r, sessionCookie))
	if err != nil || a.sessionRevoked(sc) {
		return false
	}
	var claims stepUpClaims
	if parseJWTMulti(a.verifySecrets(), a.cookieValue(r, stepUpCookie), &claims, audStepUp) != nil {
		return false
	}
	if claims.Subject != sc.Subject || claims.IssuedAt == nil {
		return false
	}
	if factor != "" && claims.Factor != factor {
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
	// Throttle: reauth verifies a password OR the same brute-forceable 6-digit TOTP code space that
	// /2fa/verify guards, so a session that hasn't proven the second factor must not hammer it.
	if a.ipLimiter != nil && !a.ipLimiter.Allow("reauth:"+c.rateIP()) {
		c.tooMany("too many attempts — wait and try again")
		return
	}
	if a.acctLimiter != nil && !a.acctLimiter.Allow("reauth:"+au.Sub) {
		c.tooMany("too many attempts — wait and try again")
		return
	}
	var body struct{ Password, Code string }
	_ = c.ShouldBindJSON(&body)
	// A code checked here is the code /auth/2fa/verify checks: one budget for both, so a session
	// doesn't get a second set of guesses at it.
	if body.Code != "" && a.acctLimiter != nil && !a.acctLimiter.Allow("2fa:"+au.Sub) {
		c.tooMany("too many attempts — wait and try again")
		return
	}

	// A code, when sent, is what is checked: it is the stronger proof, and the step-up records which
	// factor made it (adding a sign-in method to a TOTP account takes the code — factorChangeAllowed).
	ok, factor := false, ""
	if body.Code != "" && a.twoFactor != nil {
		if info, ierr := a.twoFactor.TOTP(au.ID); ierr == nil && info != nil && info.Enabled {
			ok, factor = a.verifySecondFactor(au.ID, info, body.Code), stepUpCode
		}
	}
	if !ok && body.Password != "" {
		if hash, _, perr := a.passwordHash(au.ID); perr == nil {
			ok, factor = bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) == nil, stepUpPassword
		}
	}
	if !ok {
		a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "reauth", "reauth", false, "")
		c.JSON(http.StatusForbidden, H{"error": "re-authentication failed"})
		return
	}
	a.setStepUpCookie(c, au.Sub, factor)
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "reauth", "reauth", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}
