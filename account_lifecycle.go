package authx

import (
	"errors"
	"net/http"
	"net/url"
	"time"
)

// accountStepUpMaxAge is how recently the user must have re-authenticated (POST /auth/reauth) to
// perform a destructive self-service account action (delete, change-email).
const accountStepUpMaxAge = 10 * time.Minute

// AccountDelete (DELETE /auth/api/account) hard-deletes the signed-in user's account after a fresh
// step-up. Irreversible: it cascades credentials/passkeys/tokens/OAuth/2FA, anonymizes the audit
// trail, revokes all sessions, and clears the caller's cookies. Data your app keyed on the user's Sub
// is your responsibility to remove — that boundary ends at this library's tables.
func (a *Authenticator) AccountDelete(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	if !a.StepUpFresh(c.Request, accountStepUpMaxAge) {
		c.JSON(http.StatusForbidden, H{"error": "reauth_required"})
		return
	}
	// Record before the delete so DeleteUser can anonymize this row too (keeps the event, drops PII).
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "account", "self_delete", true, "")
	if err := a.creds.DeleteUser(au.ID); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not delete your account"})
		return
	}
	if a.sessions != nil {
		_ = a.sessions.RevokeAllForUser(au.Sub)
	}
	a.clearCookie(c, sessionCookie)
	a.clearCookie(c, csrfCookie)
	a.clearCookie(c, stepUpCookie)
	c.JSON(http.StatusOK, H{"ok": true})
}

// AccountChangeEmailRequest (POST /auth/api/account/email) starts a verified email change after a fresh
// step-up: it emails a confirmation link to the NEW address and never writes the new email until that
// link is redeemed (preserving the verified-email invariant), and notifies the OLD address.
func (a *Authenticator) AccountChangeEmailRequest(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	if !a.StepUpFresh(c.Request, accountStepUpMaxAge) {
		c.JSON(http.StatusForbidden, H{"error": "reauth_required"})
		return
	}
	if a.email == nil || !a.email.Configured() {
		c.JSON(http.StatusNotImplemented, H{"error": "email is not configured"})
		return
	}
	// Rate-limit: this handler emails a caller-chosen address, so throttle it like the other
	// email-sending endpoints (otherwise a single stepped-up session is an email-bomb primitive).
	if a.ipLimiter != nil && !a.ipLimiter.Allow("changeemail:"+c.rateIP()) {
		c.tooMany("too many attempts — wait and try again")
		return
	}
	if a.acctLimiter != nil && !a.acctLimiter.Allow("changeemail:"+au.Sub) {
		c.tooMany("too many attempts — wait and try again")
		return
	}
	var body struct{ NewEmail string }
	_ = c.ShouldBindJSON(&body)
	newEmail := normEmail(body.NewEmail)
	if !validEmail(newEmail) {
		c.JSON(http.StatusBadRequest, H{"error": "enter a valid email address"})
		return
	}
	if newEmail == normEmail(au.Email) {
		c.JSON(http.StatusBadRequest, H{"error": "that's already your email address"})
		return
	}
	// The caller is authenticated + stepped-up, so a clear conflict is acceptable (and better UX than
	// silently emailing a stranger). Redemption re-checks via SetEmail's unique constraint anyway.
	if other, e := a.creds.UserByEmail(newEmail); e == nil && other != nil {
		c.JSON(http.StatusConflict, H{"error": "that email is already in use"})
		return
	}
	raw, hash := newToken()
	if a.creds.CreateToken(purposeChangeEmail, au.ID, newEmail, hash, time.Now().Add(ttlChangeEmail)) != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start the email change"})
		return
	}
	link := a.baseURL() + "/auth/email/change?token=" + raw
	_ = a.sendAuthEmail(newEmail, "Confirm your new email", "Confirm your new email",
		"Confirm this address to make it your new sign-in email. This link is valid for 1 hour.",
		"Confirm email", link, "If you didn't request this, you can ignore this email.")
	// Security-awareness notice to the OLD address (do not block on it).
	_ = a.sendAuthEmail(au.Email, "Email change requested", "Email change requested",
		"A change of your account email to "+newEmail+" was requested. If this wasn't you, sign in and secure your account.",
		"Review account", a.baseURL()+"/login", "")
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "account", "change_email_requested", true, newEmail)
	c.JSON(http.StatusOK, H{"ok": true, "message": "Check your new inbox to confirm the change."})
}

// EmailChangeConfirm (GET /auth/email/change?token=) redeems the new-address confirmation token and
// rebinds the email. Redeeming proves control of the new address, so it lands verified.
func (a *Authenticator) EmailChangeConfirm(c *reqCtx) {
	fail := func(msg string) {
		c.Redirect(http.StatusFound, a.baseURL()+"/login?error="+url.QueryEscape(msg))
	}
	token := c.Query("token")
	if token == "" {
		fail("missing token")
		return
	}
	claim, err := a.creds.ConsumeToken(purposeChangeEmail, hashToken(token))
	if err != nil {
		fail("this link is invalid or has expired")
		return
	}
	if serr := a.creds.SetEmail(claim.UserID, claim.Email); serr != nil {
		if errors.Is(serr, ErrEmailConflict) {
			fail("that email is now in use by another account")
			return
		}
		fail("could not update your email")
		return
	}
	a.creds.RecordAudit(claim.UserID, claim.Email, c.ClientIP(), "account", "email_changed", true, "")
	c.Redirect(http.StatusFound, a.baseURL()+"/login?message="+url.QueryEscape("Your email has been updated — please sign in."))
}
