package authx

import (
	"net/http"
	"net/url"
	"time"
)

// issuerName is the otpauth:// issuer label shown in the user's authenticator app (the app host, or
// a fallback).
func (a *Authenticator) issuerName() string {
	if a.cfg.AppURL != "" {
		if u, err := url.Parse(a.cfg.AppURL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return "go-auth-x"
}

// withMFAMarker appends ?mfa=required to a redirect target so the SPA (after a magic-link / social
// redirect) knows to show the 2FA prompt; it can also confirm via GET /auth/2fa/pending.
func withMFAMarker(next string) string {
	u, err := url.Parse(next)
	if err != nil {
		return next
	}
	q := u.Query()
	q.Set("mfa", "required")
	u.RawQuery = q.Encode()
	return u.String()
}

// TOTPBegin (POST /auth/2fa/totp/begin, session-gated) starts enrollment: generate a fresh secret
// (pending, not yet enabled) and return the otpauth:// URI + base32 secret. The consumer renders the
// QR; enrollment completes at /confirm with a valid code.
func (a *Authenticator) TOTPBegin(c *reqCtx) {
	au := a.two2FAUser(c)
	if au == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	if info, _ := a.twoFactor.TOTP(au.ID); info != nil && info.Enabled {
		c.JSON(http.StatusConflict, H{"error": "two-factor auth is already enabled"})
		return
	}
	secret, serr := newTOTPSecret()
	if serr != nil || a.twoFactor.SetTOTPSecret(au.ID, secret) != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start enrollment"})
		return
	}
	c.JSON(http.StatusOK, H{"secret": secret, "uri": totpURI(secret, a.issuerName(), au.Email)})
}

// TOTPConfirm (POST /auth/2fa/totp/confirm, session-gated) finishes enrollment: validate a code
// against the pending secret, enable TOTP, and return single-use recovery codes ONCE.
func (a *Authenticator) TOTPConfirm(c *reqCtx) {
	au := a.two2FAUser(c)
	if au == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	var body struct{ Code string }
	if c.ShouldBindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	info, ierr := a.twoFactor.TOTP(au.ID)
	if ierr != nil || info == nil || info.Secret == "" {
		c.JSON(http.StatusBadRequest, H{"error": "start enrollment first"})
		return
	}
	step, ok := totpValidate(info.Secret, body.Code, time.Now())
	if !ok {
		c.JSON(http.StatusBadRequest, H{"error": "that code is not valid"})
		return
	}
	codes, hashes, gerr := newRecoveryCodes(recoveryCodeCount)
	if gerr != nil || a.twoFactor.EnableTOTP(au.ID) != nil || a.twoFactor.ReplaceRecoveryCodes(au.ID, hashes) != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not enable 2fa"})
		return
	}
	_ = a.twoFactor.SetTOTPLastStep(au.ID, step)
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "2fa", "totp_enabled", true, "")
	c.JSON(http.StatusOK, H{"ok": true, "recoveryCodes": codes})
}

// TOTPDisable (POST /auth/2fa/disable, session-gated) turns 2FA off, requiring a current TOTP or
// recovery code so a walked-up session can't silently disable it.
func (a *Authenticator) TOTPDisable(c *reqCtx) {
	au := a.two2FAUser(c)
	if au == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	// Throttle: disabling verifies the same brute-forceable 6-digit code space as /2fa/verify.
	if a.ipLimiter != nil && !a.ipLimiter.Allow("2fa:"+c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, H{"error": "too many attempts — wait and try again"})
		return
	}
	var body struct{ Code string }
	_ = c.ShouldBindJSON(&body)
	info, ierr := a.twoFactor.TOTP(au.ID)
	if ierr != nil || info == nil || !info.Enabled {
		c.JSON(http.StatusBadRequest, H{"error": "two-factor auth is not enabled"})
		return
	}
	if !a.verifySecondFactor(au.ID, info, body.Code) {
		c.JSON(http.StatusForbidden, H{"error": "a valid code is required to disable 2fa"})
		return
	}
	if a.twoFactor.DisableTOTP(au.ID) != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not disable 2fa"})
		return
	}
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "2fa", "totp_disabled", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}

// TwoFactorVerify (POST /auth/2fa/verify) completes a login halted for a second factor: read the
// short-lived 2fa-pending cookie, validate a TOTP code OR consume a recovery code, then mint the
// real session.
func (a *Authenticator) TwoFactorVerify(c *reqCtx) {
	if a.twoFactor == nil {
		c.JSON(http.StatusNotFound, H{"error": "2fa not enabled"})
		return
	}
	// Throttle second-factor guessing (a 6-digit code space in a short window is brute-forceable).
	if a.ipLimiter != nil && !a.ipLimiter.Allow("2fa:"+c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, H{"error": "too many attempts — wait and try again"})
		return
	}
	tok, _ := c.Cookie(twoFactorPendingCookie)
	pc, err := a.parsePending(tok)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "your login session expired — sign in again"})
		return
	}
	if a.acctLimiter != nil && !a.acctLimiter.Allow("2fa:"+pc.Subject) {
		c.JSON(http.StatusTooManyRequests, H{"error": "too many attempts — wait and try again"})
		return
	}
	u, uerr := a.creds.UserBySub(pc.Subject)
	if uerr != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "sign in again"})
		return
	}
	if u.Disabled { // a user disabled between the first and second factor must not complete the login
		c.JSON(http.StatusForbidden, H{"error": "this account has been disabled"})
		return
	}
	var body struct{ Code string }
	if c.ShouldBindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	info, ierr := a.twoFactor.TOTP(u.ID)
	if ierr != nil || info == nil || !info.Enabled {
		c.JSON(http.StatusBadRequest, H{"error": "two-factor auth is not enabled"})
		return
	}
	if !a.verifySecondFactor(u.ID, info, body.Code) {
		a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "2fa", "verify", false, "bad_code")
		c.JSON(http.StatusUnauthorized, H{"error": "that code is not valid"})
		return
	}
	if err := a.completePendingLogin(c, pc); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "2fa", "verify", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}

// TwoFactorPending (GET /auth/2fa/pending) reports whether a login is awaiting a second factor — the
// SPA uses it after a social/OIDC redirect to decide whether to show the 2FA prompt.
func (a *Authenticator) TwoFactorPending(c *reqCtx) {
	tok, _ := c.Cookie(twoFactorPendingCookie)
	_, err := a.parsePending(tok)
	c.JSON(http.StatusOK, H{"pending": err == nil})
}

// verifySecondFactor accepts a valid TOTP code (guarding replay atomically via ClaimTOTPStep) OR a
// single-use recovery code. The replay check + last-step write are one atomic store operation so
// concurrent requests can't both accept the same code (TOCTOU); a store error fails closed.
func (a *Authenticator) verifySecondFactor(userID uint, info *TOTPInfo, code string) bool {
	if step, ok := totpValidate(info.Secret, code, time.Now()); ok {
		claimed, err := a.twoFactor.ClaimTOTPStep(userID, step)
		return err == nil && claimed
	}
	used, _ := a.twoFactor.ConsumeRecoveryCode(userID, recoveryHash(code))
	return used
}

// two2FAUser resolves the signed-in user for a session-gated 2FA endpoint, or nil (with 2FA off /
// unauthenticated handled by the caller). Returns nil when 2FA isn't wired.
func (a *Authenticator) two2FAUser(c *reqCtx) *AuthUser {
	if a.twoFactor == nil {
		return nil
	}
	au, err := a.currentAuthUser(c)
	if err != nil {
		return nil
	}
	return au
}
