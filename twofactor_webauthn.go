package authx

import (
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkey as a second factor: a login halted for 2FA (a TOTP-enabled user) can complete the second
// step with a registered passkey instead of a TOTP/recovery code. The user is known (from the signed
// 2fa-pending cookie), so this is a NON-discoverable assertion scoped to their credentials, reusing
// the same WebAuthn machinery + 2fa-pending flow as the code path.

// pendingUser resolves the user + claims from the 2fa-pending cookie (nil if absent/expired).
func (a *Authenticator) pendingUser(c *reqCtx) (*AuthUser, *pendingClaims) {
	tok, _ := c.Cookie(twoFactorPendingCookie)
	pc, err := a.parsePending(tok)
	if err != nil {
		return nil, nil
	}
	u, uerr := a.creds.UserBySub(pc.Subject)
	if uerr != nil {
		return nil, nil
	}
	return u, pc
}

// TwoFactorWebauthnBegin (POST /auth/2fa/webauthn/begin) starts a passkey assertion for the pending
// user's registered credentials.
func (a *Authenticator) TwoFactorWebauthnBegin(c *reqCtx) {
	if a.twoFactor == nil || a.wauthn == nil {
		c.JSON(http.StatusNotFound, H{"error": "2fa passkey not available"})
		return
	}
	u, _ := a.pendingUser(c)
	if u == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "your login session expired — sign in again"})
		return
	}
	wu, err := a.wauthnUserFor(u)
	if err != nil || len(wu.creds) == 0 {
		c.JSON(http.StatusBadRequest, H{"error": "no passkey registered on this account"})
		return
	}
	assertion, sd, err := a.wauthn.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start passkey verification"})
		return
	}
	if err := a.setWauthnFlow(c, sd); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start passkey verification"})
		return
	}
	c.JSON(http.StatusOK, assertion)
}

// TwoFactorWebauthnFinish (POST /auth/2fa/webauthn/finish) verifies the passkey assertion and, on
// success, mints the real session — completing the login halted for a second factor.
func (a *Authenticator) TwoFactorWebauthnFinish(c *reqCtx) {
	if a.twoFactor == nil || a.wauthn == nil {
		c.JSON(http.StatusNotFound, H{"error": "2fa passkey not available"})
		return
	}
	u, pc := a.pendingUser(c)
	if u == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "your login session expired — sign in again"})
		return
	}
	sd, err := a.getWauthnFlow(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "verification expired — try again"})
		return
	}
	a.clearCookie(c, wauthnFlowCookie)
	wu, werr := a.wauthnUserFor(u)
	if werr != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	cred, err := a.wauthn.FinishLogin(wu, *sd, c.Request)
	if err != nil {
		a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "2fa", "webauthn_verify", false, "")
		c.JSON(http.StatusUnauthorized, H{"error": "passkey verification failed"})
		return
	}
	if cred.Authenticator.CloneWarning { // possible cloned credential — refuse
		a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "passkey", "clone_warning", false, "")
		c.JSON(http.StatusUnauthorized, H{"error": "passkey verification failed (security check)"})
		return
	}
	_ = a.creds.TouchPasskey(cred.ID, cred.Authenticator.SignCount)
	if err := a.completePendingLogin(c, pc); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "2fa", "webauthn_verify", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}
