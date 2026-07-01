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
func (a *Authenticator) completeLogin(c *reqCtx, id Identity, remember bool) (twoFactorRequired bool, err error) {
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
	// Enrich the session with the user's groups (for per-group access control) when a directory
	// is wired and the upstream identity didn't already carry groups (e.g. local/social logins;
	// OIDC logins keep the IdP-asserted groups).
	if a.dir != nil && u != nil && len(id.Groups) == 0 {
		if gs, gerr := a.dir.UserGroups(u.ID); gerr == nil {
			id.Groups = groupNames(gs)
		}
	}
	// Second-factor gate: if the user has confirmed TOTP, don't mint the session yet — stash the
	// half-authenticated identity in a signed, short-lived pending cookie and require a code.
	if u != nil && a.userHasTOTP(u.ID) {
		pending, perr := a.mintPending(Identity{Subject: id.Subject, Email: id.Email, Name: id.Name, Groups: id.Groups}, role, remember)
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
	session, serr := mintSession(a.cfg.SessionSecret, id.Subject, id.Email, id.Name, role, "", id.Groups, time.Now(), ttl)
	if serr != nil {
		return false, serr
	}
	a.setCookie(c, sessionCookie, session, int(ttl/time.Second))
	a.issueCSRF(c)
	a.clearCookie(c, flowCookie)
	return false, nil
}
