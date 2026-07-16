package authx

import (
	"time"
)

// completeLogin is the single funnel every in-app auth method ends in — the same final
// steps the OIDC Callback performs. The caller has ALREADY authenticated the user
// (password verified / passkey asserted / token redeemed / social verified) and resolved
// the local User, so id.Subject MUST be that user's stable Sub. It runs the Authorizer
// (multi-tenant provisioning: upsert user, accept invites, auto-provision account), mints
// the session cookie, issues a CSRF token, and clears in-flight auth cookies.
//
// Because all four methods funnel here, no method can mint a session that bypasses
// provisioning or the disabled/verified gates the callers enforce before calling in.
// It returns twoFactorRequired=true when the user has confirmed TOTP: instead of the full session it
// sets a short-lived 2fa-pending cookie, and the caller must tell the client to finish at
// POST /auth/2fa/verify. Otherwise it mints the session and returns false.
// firstFactorCred, when non-nil, is the WebAuthn credential ID that satisfied the FIRST factor (a
// primary passkey login). It is carried into the 2fa-pending cookie so passkey-as-2FA can refuse the
// SAME credential as the second factor (a different passkey, or TOTP/recovery, is still accepted).
func (a *Authenticator) completeLogin(c *reqCtx, id Identity, remember bool, firstFactorCred []byte) (twoFactorRequired bool, err error) {
	var role string
	if a.authorizer != nil {
		r, aerr := a.authorizer.Authorize(c.Request.Context(), id)
		if aerr != nil {
			return false, aerr
		}
		role = r
	}
	// Resolve the local user once (for group enrichment + the 2FA check).
	var u *AuthUser
	if a.creds != nil {
		u, _ = a.creds.UserBySub(id.Subject)
	}
	// Enrich the session with the user's GLOBAL groups (for per-group access control) when a
	// directory is wired and the upstream identity didn't already carry groups (e.g. local/social
	// logins; OIDC logins keep the IdP-asserted groups). Org-scoped groups are filtered out —
	// their names collide across orgs, so they are checked live (RequireOrgGroupsHTTP), never
	// baked into the cookie.
	if a.dir != nil && u != nil && len(id.Groups) == 0 {
		if gs, gerr := a.dir.UserGroups(u.ID); gerr == nil {
			id.Groups = groupNames(globalGroups(gs))
		}
	}
	// Second-factor gate: if the user has confirmed TOTP, don't mint the session yet — stash the
	// half-authenticated identity in a signed, short-lived pending cookie and require a code.
	if u != nil && a.userHasTOTP(u.ID) {
		pending, perr := a.mintPending(Identity{Subject: id.Subject, Email: id.Email, Name: id.Name, Groups: id.Groups}, role, remember, firstFactorCred)
		if perr != nil {
			return false, perr
		}
		a.setCookie(c, twoFactorPendingCookie, pending, int(twoFactorPendingTTL/time.Second))
		a.clearCookie(c, flowCookie)
		return true, nil
	}
	ttl := sessionTTL
	if remember {
		ttl = rememberTTL
	}
	// Active-org enrichment: a sole org membership becomes the session's active org (several = none;
	// the app prompts and switches). Cookie-carried like groups, re-verified live by the org gates.
	var orgID, orgRole string
	if a.orgs != nil && u != nil {
		orgID, orgRole = a.defaultOrgClaims(u.ID)
	}
	sid := a.newSessionID()
	session, serr := mintSessionWith(a.cfg.SessionSecret, SessionClaims{
		Email: id.Email, Name: id.Name, Groups: id.Groups, Role: role, SID: sid, Org: orgID, OrgRole: orgRole,
	}, id.Subject, time.Now(), ttl)
	if serr != nil {
		return false, serr
	}
	var uid string
	if u != nil {
		uid = u.ID
	}
	// Record BEFORE issuing the cookie so a lost RecordSession write fails the login cleanly instead of
	// minting a session that IsRevoked would reject on its next request.
	if rerr := a.recordSession(c.Request, sid, id.Subject, uid, ttl); rerr != nil {
		return false, rerr
	}
	a.setCookie(c, sessionCookie, session, int(ttl/time.Second))
	a.issueCSRF(c)
	a.clearCookie(c, flowCookie)
	return false, nil
}
