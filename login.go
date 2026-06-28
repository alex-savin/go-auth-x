package authx

import (
	"time"

	"github.com/gin-gonic/gin"
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
func (a *Authenticator) completeLogin(c *gin.Context, id Identity, remember bool) error {
	var role string
	if a.authorizer != nil {
		r, err := a.authorizer.Authorize(c.Request.Context(), id)
		if err != nil {
			return err
		}
		role = r
	}
	// Enrich the session with the user's groups (for per-group access control) when a directory
	// is wired and the upstream identity didn't already carry groups (e.g. local/social logins;
	// OIDC logins keep the IdP-asserted groups).
	if a.dir != nil && a.creds != nil && len(id.Groups) == 0 {
		if u, uerr := a.creds.UserBySub(id.Subject); uerr == nil {
			if gs, gerr := a.dir.UserGroups(u.ID); gerr == nil {
				id.Groups = groupNames(gs)
			}
		}
	}
	ttl := sessionTTL
	if remember {
		ttl = rememberTTL
	}
	session, err := mintSession(a.cfg.SessionSecret, id.Subject, id.Email, id.Name, role, "", id.Groups, time.Now(), ttl)
	if err != nil {
		return err
	}
	a.setCookie(c, sessionCookie, session, int(ttl/time.Second))
	a.issueCSRF(c)
	a.clearCookie(c, flowCookie)
	return nil
}
