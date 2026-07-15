package authx

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// impersonationTTL bounds an admin impersonation session — deliberately short.
const impersonationTTL = 30 * time.Minute

// adminCreateUser (POST /auth/admin/users) provisions a local user, optionally with a password and/or
// pre-verified email. The password (if any) still passes the full policy + breach gate.
func (a *Authenticator) adminCreateUser(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if a.creds == nil {
		a.adminFail(c, http.StatusNotImplemented, "local credential store not configured", nil)
		return
	}
	var body struct {
		Email, Name, Password string
		EmailVerified         bool
	}
	if err := c.ShouldBindJSON(&body); err != nil || !validEmail(normEmail(body.Email)) {
		c.JSON(http.StatusBadRequest, H{"error": "a valid email is required"})
		return
	}
	email := normEmail(body.Email)
	if body.Password != "" {
		if msg := a.passwordPolicyError(c.Request.Context(), body.Password, email); msg != "" {
			c.JSON(http.StatusBadRequest, H{"error": msg})
			return
		}
	}
	u, err := a.creds.CreateLocalUser(email, strings.TrimSpace(body.Name))
	if err != nil {
		if errors.Is(err, ErrEmailConflict) {
			c.JSON(http.StatusConflict, H{"error": "an account already exists for this email"})
			return
		}
		a.adminFail(c, http.StatusInternalServerError, "could not create user", err)
		return
	}
	if body.Password != "" {
		hash, herr := hashPassword(body.Password)
		if herr != nil || a.creds.SetPasswordHash(u.ID, hash, "bcrypt") != nil {
			// Don't leave a passwordless account the admin believes has a password — roll it back.
			_ = a.creds.DeleteUser(u.ID)
			a.adminFail(c, http.StatusInternalServerError, "could not set the user's password", herr)
			return
		}
	}
	if body.EmailVerified {
		if err := a.creds.SetEmailVerified(u.ID, true); err != nil {
			a.adminFail(c, http.StatusInternalServerError, "user created but could not be verified", err)
			return
		}
		u.EmailVerified = true
	}
	c.JSON(http.StatusOK, H{"ok": true, "user": u})
}

// adminSetPassword (POST /auth/admin/users/{id}/password) sets/resets a user's password (policy-checked).
func (a *Authenticator) adminSetPassword(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if a.creds == nil {
		a.adminFail(c, http.StatusNotImplemented, "local credential store not configured", nil)
		return
	}
	id, ok := paramUint(c, "id")
	if !ok {
		return
	}
	u, err := a.dir.UserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, H{"error": "no such user"})
		return
	}
	var body struct{ Password string }
	_ = c.ShouldBindJSON(&body)
	if msg := a.passwordPolicyError(c.Request.Context(), body.Password, u.Email); msg != "" {
		c.JSON(http.StatusBadRequest, H{"error": msg})
		return
	}
	hash, herr := hashPassword(body.Password)
	if herr != nil || a.creds.SetPasswordHash(id, hash, "bcrypt") != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not set password", herr)
		return
	}
	a.creds.RecordAudit(id, u.Email, c.ClientIP(), "admin", "set_password", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}

// adminDeleteUser (DELETE /auth/admin/users/{id}) hard-deletes a user (cascade + audit anonymization)
// and revokes their sessions if session tracking is on.
func (a *Authenticator) adminDeleteUser(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if a.creds == nil {
		a.adminFail(c, http.StatusNotImplemented, "local credential store not configured", nil)
		return
	}
	id, ok := paramUint(c, "id")
	if !ok {
		return
	}
	u, uerr := a.dir.UserByID(id)
	if err := a.creds.DeleteUser(id); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not delete user", err)
		return
	}
	if a.sessions != nil && uerr == nil {
		_ = a.sessions.RevokeAllForUser(u.Sub)
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

// adminSetBan (POST /auth/admin/users/{id}/ban) sets or clears a time-boxed ban with a reason. When
// banning and session tracking is on, live sessions are revoked so the ban takes effect immediately.
func (a *Authenticator) adminSetBan(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramUint(c, "id")
	if !ok {
		return
	}
	var body struct {
		Banned bool
		Reason string
		Until  *string // optional RFC3339; nil/empty = permanent while banned
	}
	_ = c.ShouldBindJSON(&body)
	var until *time.Time
	if body.Until != nil && *body.Until != "" {
		t, perr := time.Parse(time.RFC3339, *body.Until)
		if perr != nil {
			c.JSON(http.StatusBadRequest, H{"error": "until must be RFC3339"})
			return
		}
		until = &t
	}
	if err := a.dir.SetUserBan(id, body.Banned, until, strings.TrimSpace(body.Reason)); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not update ban", err)
		return
	}
	u, _ := a.dir.UserByID(id)
	event := "unban"
	if body.Banned {
		event = "ban"
	}
	if a.creds != nil { // leave a forensic trail for this security-relevant admin action
		email := ""
		if u != nil {
			email = u.Email
		}
		a.creds.RecordAudit(id, email, c.ClientIP(), "admin", event, true, strings.TrimSpace(body.Reason))
	}
	if body.Banned && a.sessions != nil && u != nil {
		_ = a.sessions.RevokeAllForUser(u.Sub)
	}
	c.JSON(http.StatusOK, H{"ok": true, "banned": body.Banned})
}

// adminImpersonate (POST /auth/admin/users/{id}/impersonate) mints a short-lived session for the target
// user carrying an ImpersonatedBy marker. It mints directly (NOT through completeLogin) so the target's
// own 2FA gate doesn't challenge the admin, and stamps the admin's subject for the audit + the banner.
func (a *Authenticator) adminImpersonate(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramUint(c, "id")
	if !ok {
		return
	}
	target, err := a.dir.UserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, H{"error": "no such user"})
		return
	}
	// NOTE: the disabled/banned login gate is intentionally NOT applied here — an operator may need to
	// impersonate a suspended user to investigate. This is safe: the endpoint is adminGuard-protected,
	// the ImpersonatedBy marker blocks re-escalation through adminGuard, the session is short-lived
	// (impersonationTTL) and audited, and it mints outside completeLogin by design.
	// Resolve a NON-EMPTY impersonator marker. ImpersonatedBy == "" is the "not impersonating" sentinel,
	// so an API-key caller (no session cookie) must be stamped as apikey:<id> — never left blank, which
	// would mint a genuine-looking session (and, if the target is the owner, a real owner session).
	adminSub := ""
	if sc := a.sessionOf(c); sc != nil {
		adminSub = sc.Subject
	} else if key := bearerToken(c.GetHeader("Authorization")); key != "" {
		if info, ok := a.ValidateAPIKey(key); ok {
			adminSub = "apikey:" + strconv.FormatUint(uint64(info.ID), 10)
		}
	}
	if adminSub == "" {
		c.JSON(http.StatusForbidden, H{"error": "impersonation requires an identifiable admin actor"})
		return
	}
	var groups []string
	if gs, gerr := a.dir.UserGroups(id); gerr == nil {
		groups = groupNames(gs)
	}
	sid := a.newSessionID()
	sess, serr := mintSessionWith(a.cfg.SessionSecret, SessionClaims{
		Email: target.Email, Name: target.Name, Groups: groups, SID: sid, ImpersonatedBy: adminSub,
	}, target.Sub, time.Now(), impersonationTTL)
	if serr != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not impersonate"})
		return
	}
	// Record before the cookie (see completeLogin) so an unrecorded impersonation session isn't
	// immediately rejected by the fail-closed revocation check.
	if rerr := a.recordSession(c.Request, sid, target.Sub, id, impersonationTTL); rerr != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not impersonate"})
		return
	}
	a.setCookie(c, sessionCookie, sess, int(impersonationTTL/time.Second))
	a.issueCSRF(c)
	if a.creds != nil {
		a.creds.RecordAudit(id, target.Email, c.ClientIP(), "admin", "impersonate_start", true, adminSub)
	}
	c.JSON(http.StatusOK, H{"ok": true, "impersonating": target.Email})
}

// StopImpersonating (POST /auth/api/stop-impersonating) ends an impersonation session. It revokes the
// impersonation session and clears the cookies; the admin then signs back in with their own account
// (clean, and it avoids resurrecting a dropped OIDC id_token from the original admin session).
func (a *Authenticator) StopImpersonating(c *reqCtx) {
	sc := a.sessionOf(c)
	if sc == nil || sc.ImpersonatedBy == "" {
		c.JSON(http.StatusBadRequest, H{"error": "not impersonating"})
		return
	}
	if sc.SID != "" && a.sessions != nil {
		_ = a.sessions.RevokeSession(sc.SID)
	}
	if a.creds != nil { // record the end of the impersonation for a complete accountability trail
		a.creds.RecordAudit(0, sc.Email, c.ClientIP(), "admin", "impersonate_stop", true, sc.ImpersonatedBy)
	}
	a.clearCookie(c, sessionCookie)
	a.clearCookie(c, csrfCookie)
	c.JSON(http.StatusOK, H{"ok": true})
}

// adminListUserSessions (GET /auth/admin/users/{id}/sessions) lists a user's active sessions.
func (a *Authenticator) adminListUserSessions(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if a.sessions == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "session management not available"})
		return
	}
	id, ok := paramUint(c, "id")
	if !ok {
		return
	}
	u, err := a.dir.UserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, H{"error": "no such user"})
		return
	}
	recs, lerr := a.sessions.ListSessionsForUser(u.Sub)
	if lerr != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list sessions", lerr)
		return
	}
	c.JSON(http.StatusOK, H{"sessions": recs})
}

// adminRevokeUserSessions (POST /auth/admin/users/{id}/sessions/revoke) signs a user out everywhere.
func (a *Authenticator) adminRevokeUserSessions(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if a.sessions == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "session management not available"})
		return
	}
	id, ok := paramUint(c, "id")
	if !ok {
		return
	}
	u, err := a.dir.UserByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, H{"error": "no such user"})
		return
	}
	if err := a.sessions.RevokeAllForUser(u.Sub); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not revoke sessions", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}
