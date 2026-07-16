package authx

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// orgActor resolves the calling session AND its credential-store user for the self-service org
// endpoints (which are registered on the public /auth group, so they self-gate like the account
// endpoints). Writes the 401 itself on a miss.
func (a *Authenticator) orgActor(c *reqCtx) (*SessionClaims, *AuthUser, bool) {
	sc := a.sessionOf(c)
	if sc == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return nil, nil, false
	}
	u, err := a.creds.UserBySub(sc.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return nil, nil, false
	}
	return sc, u, true
}

// remintWithOrg re-issues the session cookie with a new active org, preserving every other claim
// AND the remaining lifetime (a switch must not extend the session). The SID is kept, so the
// server-side session record — and any revocation of it — still applies.
func (a *Authenticator) remintWithOrg(c *reqCtx, sc *SessionClaims, orgID, orgRole string) error {
	if sc.ExpiresAt == nil {
		return errors.New("session has no expiry")
	}
	ttl := time.Until(sc.ExpiresAt.Time)
	if ttl <= 0 {
		return errors.New("session expired")
	}
	base := *sc
	base.Org = orgID
	base.OrgRole = orgRole
	session, err := mintSessionWith(a.cfg.SessionSecret, base, sc.Subject, time.Now(), ttl)
	if err != nil {
		return err
	}
	a.setCookie(c, sessionCookie, session, int(ttl/time.Second))
	return nil
}

// orgView is the JSON projection of an org for the self-service endpoints.
func orgView(o *Org) H { return H{"id": o.ID, "slug": o.Slug, "name": o.Name} }

// userOrgViews flattens memberships to the org-picker JSON shape — the single projection behind
// both GET /auth/orgs and /auth/me, so the two can't drift.
func userOrgViews(ms []UserOrg) []H {
	out := make([]H, 0, len(ms))
	for i := range ms {
		v := orgView(&ms[i].Org)
		v["role"] = ms[i].Role
		out = append(out, v)
	}
	return out
}

// normOrgRole trims and validates a role token from a request body, applying def when empty
// (an empty def makes the role required). Writes the 400 itself — the single validation +
// message shared by every role-accepting endpoint.
func normOrgRole(c *reqCtx, raw, def string) (string, bool) {
	role := strings.TrimSpace(raw)
	if role == "" {
		role = def
	}
	if !validOrgRole(role) {
		c.JSON(http.StatusBadRequest, H{"error": "role must be 1–32 chars of a-z, 0-9, '-' or '_'"})
		return "", false
	}
	return role, true
}

// orgMemberView projects a member without the operator-only AuthUser fields (ban/disabled state
// stays admin-API-only; fellow members only need identity + role).
func orgMemberView(m OrgMember) H {
	return H{"id": m.User.ID, "email": m.User.Email, "name": m.User.Name, "role": m.Role}
}

// OrgList (GET /auth/orgs) lists the signed-in user's org memberships plus the active org, for
// the app's org picker.
func (a *Authenticator) OrgList(c *reqCtx) {
	sc, u, ok := a.orgActor(c)
	if !ok {
		return
	}
	ms, err := a.orgs.UserOrgs(u.ID)
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list organizations", err)
		return
	}
	c.JSON(http.StatusOK, H{"orgs": userOrgViews(ms), "active": sc.Org})
}

// OrgSwitch (POST /auth/org/switch) changes the session's ACTIVE org after verifying LIVE
// membership, re-minting the cookie with its remaining lifetime. Body: {"slug": "<slug>"} resolves
// by slug ONLY; {"org": "<id or slug>"} resolves as an ID first, slug fallback — pass the explicit
// slug field when a slug could collide with another org's opaque ID (e.g. an all-digit slug against
// the reference stores' decimal IDs). An empty body clears the active org. Membership and existence
// failures are the same 403, so the endpoint is not an org-ID existence oracle.
func (a *Authenticator) OrgSwitch(c *reqCtx) {
	sc, u, ok := a.orgActor(c)
	if !ok {
		return
	}
	var body struct{ Org, Slug string }
	_ = c.ShouldBindJSON(&body)
	target, slug := strings.TrimSpace(body.Org), strings.TrimSpace(body.Slug)
	if target == "" && slug == "" {
		if err := a.remintWithOrg(c, sc, "", ""); err != nil {
			c.JSON(http.StatusUnauthorized, H{"error": "session expired"})
			return
		}
		c.JSON(http.StatusOK, H{"ok": true, "org": nil})
		return
	}
	var org *Org
	var err error
	if slug != "" {
		org, err = a.orgs.OrgBySlug(slug)
	} else {
		org, err = a.orgs.OrgByID(target)
		if errors.Is(err, ErrNoOrg) {
			org, err = a.orgs.OrgBySlug(target)
		}
	}
	if errors.Is(err, ErrNoOrg) {
		c.JSON(http.StatusForbidden, H{"error": "not a member of that organization"})
		return
	}
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not switch organization", err)
		return
	}
	role, err := a.orgs.OrgRole(org.ID, u.ID)
	if errors.Is(err, ErrNotOrgMember) || errors.Is(err, ErrNoOrg) {
		c.JSON(http.StatusForbidden, H{"error": "not a member of that organization"})
		return
	}
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not switch organization", err)
		return
	}
	if err := a.remintWithOrg(c, sc, org.ID, role); err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "session expired"})
		return
	}
	v := orgView(org)
	v["role"] = role
	c.JSON(http.StatusOK, H{"ok": true, "org": v})
}

// activeOrgRole resolves the actor's session, credential user, and LIVE role in their ACTIVE org —
// the single policy pipeline behind every self-service org endpoint. Sentinel misses (not a member,
// org gone) are 403; store failures are 500, never conflated with a membership denial. Writes the
// error response itself; returns ok=false to stop.
func (a *Authenticator) activeOrgRole(c *reqCtx) (sc *SessionClaims, u *AuthUser, role string, ok bool) {
	sc, u, ok = a.orgActor(c)
	if !ok {
		return nil, nil, "", false
	}
	if sc.Org == "" {
		c.JSON(http.StatusForbidden, H{"error": "no active organization"})
		return nil, nil, "", false
	}
	role, err := a.orgs.OrgRole(sc.Org, u.ID)
	if errors.Is(err, ErrNotOrgMember) || errors.Is(err, ErrNoOrg) {
		c.JSON(http.StatusForbidden, H{"error": "not a member of this organization"})
		return nil, nil, "", false
	}
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "organization check failed", err)
		return nil, nil, "", false
	}
	return sc, u, role, true
}

// activeOrgManager is activeOrgRole plus the owner/admin management gate.
func (a *Authenticator) activeOrgManager(c *reqCtx) (sc *SessionClaims, u *AuthUser, role string, ok bool) {
	sc, u, role, ok = a.activeOrgRole(c)
	if !ok {
		return nil, nil, "", false
	}
	if !orgRoleIsManager(role) {
		c.JSON(http.StatusForbidden, H{"error": "requires an organization owner or admin"})
		return nil, nil, "", false
	}
	return sc, u, role, true
}

// OrgMemberList (GET /auth/org/members) lists the ACTIVE org's members to any live member.
func (a *Authenticator) OrgMemberList(c *reqCtx) {
	sc, _, _, ok := a.activeOrgRole(c)
	if !ok {
		return
	}
	members, err := a.orgs.OrgMembers(sc.Org)
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list members", err)
		return
	}
	out := make([]H, 0, len(members))
	for _, m := range members {
		out = append(out, orgMemberView(m))
	}
	c.JSON(http.StatusOK, H{"members": out})
}

// soleOwner reports whether userID is the org's ONLY owner — the guard that keeps a self-service
// demote/remove from leaving the org unmanageable. Callers hold a.orgMu so a concurrent pair of
// removals can't both pass (process-local, like credMu; a multi-replica deployment wanting
// cross-node atomicity should also enforce this in its store).
func (a *Authenticator) soleOwner(orgID string, userID uint) (bool, error) {
	members, err := a.orgs.OrgMembers(orgID)
	if err != nil {
		return false, err
	}
	owners, isOwner := 0, false
	for _, m := range members {
		if m.Role == OrgRoleOwner {
			owners++
			if m.User.ID == userID {
				isOwner = true
			}
		}
	}
	return isOwner && owners == 1, nil
}

// OrgMemberSetRole (POST /auth/org/members/{userId}, body {"role": "..."}) changes a member's
// role in the ACTIVE org. Owner/admin only; anything touching the owner role (granting it, or
// changing an existing owner's role) requires an owner, and the last owner can't be demoted.
func (a *Authenticator) OrgMemberSetRole(c *reqCtx) {
	sc, _, actorRole, ok := a.activeOrgManager(c)
	if !ok {
		return
	}
	uid, ok := paramUint(c, "userId")
	if !ok {
		return
	}
	var body struct{ Role string }
	_ = c.ShouldBindJSON(&body)
	newRole, ok := normOrgRole(c, body.Role, "") // no default: the role is the point of this verb
	if !ok {
		return
	}
	// The target's role is read INSIDE orgMu: the owner-only gate and the last-owner guard below
	// both branch on it, and a read taken before the lock could go stale against a concurrent
	// promote/demote — letting this request skip the sole-owner check it should have run (TOCTOU).
	a.orgMu.Lock()
	defer a.orgMu.Unlock()
	targetRole, err := a.orgs.OrgRole(sc.Org, uid)
	if errors.Is(err, ErrNotOrgMember) || errors.Is(err, ErrNoOrg) {
		c.JSON(http.StatusNotFound, H{"error": "no such member"})
		return
	}
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not update member", err)
		return
	}
	if (newRole == OrgRoleOwner || targetRole == OrgRoleOwner) && actorRole != OrgRoleOwner {
		c.JSON(http.StatusForbidden, H{"error": "only an owner may grant or change the owner role"})
		return
	}
	if targetRole == OrgRoleOwner && newRole != OrgRoleOwner {
		sole, serr := a.soleOwner(sc.Org, uid)
		if serr != nil {
			a.adminFail(c, http.StatusInternalServerError, "could not update member", serr)
			return
		}
		if sole {
			c.JSON(http.StatusConflict, H{"error": "promote another owner before demoting the last one"})
			return
		}
	}
	if err := a.orgs.SetOrgMember(sc.Org, uid, newRole); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not update member", err)
		return
	}
	a.orgAudit(c, uid, "org_role_set", sc.Org+":"+newRole)
	c.JSON(http.StatusOK, H{"ok": true, "role": newRole})
}

// OrgMemberRemove (DELETE /auth/org/members/{userId}) removes a member from the ACTIVE org.
// Owner/admin only; removing an owner requires an owner; the last owner can't be removed. A
// member may remove THEMSELF (leave) under the same guards — their cookie is re-minted with no
// active org.
func (a *Authenticator) OrgMemberRemove(c *reqCtx) {
	sc, u, actorRole, ok := a.activeOrgRole(c)
	if !ok {
		return
	}
	uid, ok := paramUint(c, "userId")
	if !ok {
		return
	}
	leaving := uid == u.ID
	if !leaving && !orgRoleIsManager(actorRole) {
		c.JSON(http.StatusForbidden, H{"error": "requires an organization owner or admin"})
		return
	}
	// Target role read INSIDE orgMu — see OrgMemberSetRole for the TOCTOU this prevents.
	a.orgMu.Lock()
	defer a.orgMu.Unlock()
	targetRole, err := a.orgs.OrgRole(sc.Org, uid)
	if errors.Is(err, ErrNotOrgMember) || errors.Is(err, ErrNoOrg) {
		c.JSON(http.StatusNotFound, H{"error": "no such member"})
		return
	}
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not remove member", err)
		return
	}
	if targetRole == OrgRoleOwner && actorRole != OrgRoleOwner {
		c.JSON(http.StatusForbidden, H{"error": "only an owner may remove an owner"})
		return
	}
	if targetRole == OrgRoleOwner {
		sole, serr := a.soleOwner(sc.Org, uid)
		if serr != nil {
			a.adminFail(c, http.StatusInternalServerError, "could not remove member", serr)
			return
		}
		if sole {
			c.JSON(http.StatusConflict, H{"error": "promote another owner before removing the last one"})
			return
		}
	}
	if err := a.orgs.RemoveOrgMember(sc.Org, uid); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not remove member", err)
		return
	}
	a.orgAudit(c, uid, "org_member_removed", sc.Org)
	if leaving {
		// Clear the leaver's own active org so their cookie doesn't keep naming an org the gates
		// will now refuse (best-effort; a failed re-mint still leaves the gates closed).
		_ = a.remintWithOrg(c, sc, "", "")
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

// --- invites ---

// orgAudit writes an org event to the audit trail (best-effort, creds is non-nil when orgs are on).
func (a *Authenticator) orgAudit(c *reqCtx, userID uint, event, detail string) {
	a.creds.RecordAudit(userID, "", c.ClientIP(), "org", event, true, detail)
}

// OrgInviteCreate (POST /auth/org/invites, body {"email","role"}) emails a single-use invite to
// join the ACTIVE org, stored as a first-class record (list with GET, revoke with DELETE /{id});
// re-inviting an address replaces its pending invite. Owner/admin only; only an owner may invite
// an owner. The link is ONLY ever emailed — possession of the token is the invitee's proof of
// mailbox control, so handing it to the inviter would let them mint memberships for addresses
// they don't own.
func (a *Authenticator) OrgInviteCreate(c *reqCtx) {
	sc, u, actorRole, ok := a.activeOrgManager(c)
	if !ok {
		return
	}
	if a.email == nil || !a.email.Configured() {
		c.JSON(http.StatusNotImplemented, H{"error": "email is not configured"})
		return
	}
	var body struct{ Email, Role string }
	_ = c.ShouldBindJSON(&body)
	email := normEmail(body.Email)
	if !validEmail(email) {
		c.JSON(http.StatusBadRequest, H{"error": "a valid email is required"})
		return
	}
	role, ok := normOrgRole(c, body.Role, OrgRoleMember)
	if !ok {
		return
	}
	if role == OrgRoleOwner && actorRole != OrgRoleOwner {
		c.JSON(http.StatusForbidden, H{"error": "only an owner may invite an owner"})
		return
	}
	// Modest per-inviter throttle (when the local limiters are wired) so a compromised org admin
	// can't turn the mailer into a spam cannon.
	if a.acctLimiter != nil && !a.acctLimiter.Allow("orginvite:"+sc.Subject) {
		c.tooMany("too many invitations — try again later")
		return
	}
	if existing, err := a.creds.UserByEmail(email); err == nil {
		if _, rerr := a.orgs.OrgRole(sc.Org, existing.ID); rerr == nil {
			c.JSON(http.StatusConflict, H{"error": "that user is already a member"})
			return
		}
	}
	org, err := a.orgs.OrgByID(sc.Org)
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not create invitation", err)
		return
	}
	raw, hash := newToken()
	inv, err := a.orgs.CreateOrgInvite(org.ID, email, role, u.Email, hash, time.Now().Add(ttlInvite))
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not create invitation", err)
		return
	}
	// Only the opaque token rides in the URL — the org and role bind to the stored record, so
	// there is nothing in the link to tamper with.
	link := a.baseURL() + "/auth/org/invite/accept?token=" + raw
	if err := a.sendAuthEmail(email, "You're invited to join "+org.Name,
		"Join "+org.Name,
		u.Email+" invited you to join "+org.Name+" on "+a.brandName()+". Sign in (or create an account) with this email address, then accept below.",
		"Accept invitation", link,
		"This invitation is valid for 7 days and can be used once. If you weren't expecting it, ignore this email."); err != nil {
		// Don't leave an unreachable-but-redeemable record behind if the mail never went out.
		_ = a.orgs.RevokeOrgInvite(org.ID, inv.ID)
		c.JSON(http.StatusInternalServerError, H{"error": "could not send the invitation email"})
		return
	}
	a.orgAudit(c, u.ID, "org_invite_sent", org.ID+":"+role+":"+email)
	c.JSON(http.StatusOK, H{"ok": true, "invite": inv})
}

// OrgInviteList (GET /auth/org/invites) lists the ACTIVE org's PENDING invitations (owner/admin) —
// the management surface a bare token could never offer.
func (a *Authenticator) OrgInviteList(c *reqCtx) {
	sc, _, _, ok := a.activeOrgManager(c)
	if !ok {
		return
	}
	invites, err := a.orgs.OrgInvites(sc.Org)
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list invitations", err)
		return
	}
	c.JSON(http.StatusOK, H{"invites": invites})
}

// OrgInviteRevoke (DELETE /auth/org/invites/{id}) cancels a pending invitation before it is
// redeemed (owner/admin). Idempotent — revoking an already-gone invite is not an error.
func (a *Authenticator) OrgInviteRevoke(c *reqCtx) {
	sc, u, _, ok := a.activeOrgManager(c)
	if !ok {
		return
	}
	id, ok := paramUint(c, "id")
	if !ok {
		return
	}
	if err := a.orgs.RevokeOrgInvite(sc.Org, id); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not revoke invitation", err)
		return
	}
	a.orgAudit(c, u.ID, "org_invite_revoked", sc.Org)
	c.JSON(http.StatusOK, H{"ok": true})
}

// OrgInviteAccept (GET /auth/org/invite/accept?token=) redeems an invite from the emailed link.
// The org and role come from the stored RECORD — nothing in the URL can be tampered with. The
// signed-in user's email must MATCH the invited address — the token proves control of that
// mailbox, so acceptance also marks the email verified (same rule as the magic link).
// Unauthenticated clicks bounce to the login page with the accept URL as next, so the invitee can
// sign in or register first. These are browser link-clicks, so failures redirect with a message
// rather than returning JSON (mirrors redeemAndLogin).
func (a *Authenticator) OrgInviteAccept(c *reqCtx) {
	fail := func(msg string) {
		c.Redirect(http.StatusFound, a.baseURL()+"/login?error="+url.QueryEscape(msg))
	}
	token := c.Query("token")
	if token == "" {
		fail("this invitation link is invalid")
		return
	}
	sc := a.sessionOf(c)
	if sc == nil {
		// Not signed in yet: round-trip through login/signup and come back to this exact URL.
		c.Redirect(http.StatusFound, a.baseURL()+"/login?next="+url.QueryEscape(c.Request.URL.RequestURI()))
		return
	}
	u, err := a.creds.UserBySub(sc.Subject)
	if err != nil {
		fail("account not found")
		return
	}
	// PEEK first: consuming is what burns the single-use token, and the wrong-account case must
	// not destroy a still-valid invitation.
	inv, err := a.orgs.PeekOrgInvite(hashToken(token))
	if err != nil {
		fail("this invitation is invalid or has expired")
		return
	}
	if normEmail(u.Email) != normEmail(inv.Email) {
		fail("this invitation was sent to a different email address — sign in with that account")
		return
	}
	org, err := a.orgs.OrgByID(inv.OrgID)
	if err != nil {
		fail("this organization no longer exists")
		return
	}
	if _, err := a.orgs.ConsumeOrgInvite(hashToken(token)); err != nil {
		fail("this invitation is invalid or has expired") // lost a redeem race — already consumed
		return
	}
	// An existing member keeps their current role — a stale invite must not demote (or escalate)
	// what they've since been granted.
	finalRole, err := a.orgs.OrgRole(org.ID, u.ID)
	if errors.Is(err, ErrNotOrgMember) {
		finalRole = inv.Role
		err = a.orgs.SetOrgMember(org.ID, u.ID, inv.Role)
	}
	if err != nil {
		// The single-use invite is already consumed (deliberately BEFORE the grant — granting
		// first would leave a live token that a later-removed member could replay). Record the
		// failed grant so an operator can see why this invitation never produced a member and
		// re-issue it.
		a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "org", "org_invite_grant_failed", false, org.ID+":"+inv.Role)
		fail("could not join the organization — ask for a new invitation")
		return
	}
	// Redeeming the emailed token proved control of the account's address.
	_ = a.creds.SetEmailVerified(u.ID, true)
	a.orgAudit(c, u.ID, "org_invite_accepted", org.ID+":"+finalRole)
	// Land the user IN the org they just joined.
	_ = a.remintWithOrg(c, sc, org.ID, finalRole)
	c.Redirect(http.StatusFound, sanitizeNext(c.Query("next")))
}
