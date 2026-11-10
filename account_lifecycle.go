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

// hasReauthFactor reports whether the user has a factor that step-up re-auth (POST /auth/reauth) can
// verify — a password or enabled TOTP. A purely passwordless (social/OIDC-only) user has neither, so a
// step-up gate would lock them out permanently; it is not a net protection loss for them, since their
// session already permits setting a password (i.e. self-service takeover) without a prior factor.
//
// A store error counts as having one: the callers then ask for a step-up, rather than waive it for a
// user whose factors couldn't be read.
func (a *Authenticator) hasReauthFactor(userID string) bool {
	if _, _, err := a.passwordHash(userID); err == nil || !errors.Is(err, ErrNoCredential) {
		return true
	}
	if a.twoFactor != nil {
		info, err := a.twoFactor.TOTP(userID)
		if err != nil {
			return !errors.Is(err, ErrNoCredential)
		}
		return info != nil && info.Enabled
	}
	return false
}

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
	// Require a fresh step-up ONLY when the user has a factor that /auth/reauth can verify. A purely
	// passwordless (social/OIDC-only) user has no password or TOTP, so demanding step-up would lock them
	// out of this action forever; for them the gated session + CSRF is the strongest available proof.
	if a.hasReauthFactor(au.ID) && !a.StepUpFresh(c.Request, accountStepUpMaxAge) {
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
	// Require a fresh step-up ONLY when the user has a factor that /auth/reauth can verify. A purely
	// passwordless (social/OIDC-only) user has no password or TOTP, so demanding step-up would lock them
	// out of this action forever; for them the gated session + CSRF is the strongest available proof.
	if a.hasReauthFactor(au.ID) && !a.StepUpFresh(c.Request, accountStepUpMaxAge) {
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
	// Taken: the same answer as a free address (no account-existence oracle); the address's owner hears
	// of it, and the confirm step re-checks uniqueness anyway.
	if other, e := a.creds.UserByEmail(newEmail); e == nil && other != nil {
		if a.acctLimiter == nil || a.acctLimiter.Allow("change-email-taken:"+newEmail) {
			_ = a.sendAuthEmail(newEmail, "Someone tried to use this address", "This address already has an account",
				"Someone signed in to another account tried to change its email to this address. It already belongs to an account, so nothing was changed.",
				"Sign in", a.baseURL()+"/login", "If this was you, sign in to the account that uses this address.")
		}
		c.JSON(http.StatusOK, H{"ok": true, "message": "Check your new inbox to confirm the change."})
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
	claim, err := a.creds.PeekToken(purposeChangeEmail, hashToken(token))
	if err != nil {
		fail("this link is invalid or has expired")
		return
	}
	// The link proves the new mailbox, not that the account still wants the change: it is confirmed
	// in a browser signed in to the account. Someone who asked for the change with a stolen password
	// or session holds the link, and after the account's owner resets the password or signs
	// everything out, no session to open it with. Not signed in: sign in and come back (the token
	// isn't spent).
	signedIn := false
	if sc := a.sessionOf(c); sc != nil && sc.ImpersonatedBy == "" {
		if u, uerr := a.creds.UserBySub(sc.Subject); uerr == nil {
			signedIn = u.ID == claim.UserID
		}
	}
	if !signedIn {
		c.Redirect(http.StatusFound, a.baseURL()+"/login?message="+url.QueryEscape("Sign in to confirm your new email address.")+
			"&next="+url.QueryEscape("/auth/email/change?token="+token))
		return
	}
	if _, err := a.creds.ConsumeToken(purposeChangeEmail, hashToken(token)); err != nil {
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

// cancelPendingEmailChange drops the user's unconfirmed email-change links (when the store can: see
// TokenRevoker). Called wherever an account is taken back — a password reset or change, signing out
// its other sessions — since whoever it is taken back from may have a change of address pending.
func (a *Authenticator) cancelPendingEmailChange(userID string) {
	if tr, ok := a.creds.(TokenRevoker); ok && userID != "" {
		_ = tr.DeleteTokens(purposeChangeEmail, userID)
	}
}
