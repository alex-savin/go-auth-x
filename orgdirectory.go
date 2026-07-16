package authx

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// OrgDirectoryStore is an OPTIONAL upgrade interface a DirectoryStore may implement to support
// org-scoped resources: groups and API keys bound to one organization (the v0.7 phase). It is
// detected via type assertion — a DirectoryStore that doesn't implement it simply has the
// org-scoped features off (the handlers 501), so existing custom stores keep compiling unchanged.
//
// Org-scoped groups live in the same namespace as global groups but are invisible to the global
// verbs: Groups()/GroupByName() return ONLY global groups, and group names are unique per
// (org, name) — two orgs may both have "engineering". Org-scoped groups never ride in the session
// cookie (see RequireOrgGroupsHTTP, which checks them live).
type OrgDirectoryStore interface {
	// Org-scoped groups. CreateOrgGroup enforces (org, name) uniqueness; OrgGroupByName returns
	// ErrNoGroup when absent. OrgOfGroup resolves which org owns a group ID ("" = global,
	// ErrNoGroup if the group doesn't exist) — the check every by-ID group operation gates on.
	CreateOrgGroup(orgID, name, description string) (*Group, error)
	OrgGroups(orgID string) ([]Group, error)
	OrgGroupByName(orgID, name string) (*Group, error)
	OrgOfGroup(groupID string) (string, error)
	UserOrgGroups(orgID, userID string) ([]Group, error)

	// Org-bound API keys. An org-bound key (OrgID != "") is refused by every GLOBAL surface
	// (adminGuard, ValidateAPIKeyScope, group merging) and only satisfies ValidateOrgAPIKeyScope
	// for ITS org. ListAPIKeys (global) still lists all keys — the OrgID field says which are bound.
	CreateOrgAPIKey(orgID, name string, groups, scopes []string, prefix string, hash []byte, expiresAt *time.Time) (*APIKeyInfo, error)
	ListOrgAPIKeys(orgID string) ([]APIKeyInfo, error)
}

// orgDir returns the directory's org-scoped upgrade interface, or nil when unsupported.
func (a *Authenticator) orgDir() OrgDirectoryStore {
	if a == nil || a.dir == nil {
		return nil
	}
	od, _ := a.dir.(OrgDirectoryStore)
	return od
}

// globalGroups filters a group list to the GLOBAL (org-less) ones — the only groups that may ride
// in the session cookie. Org-scoped group names collide across orgs, so they are checked live via
// RequireOrgGroupsHTTP instead of being baked into claims.
func globalGroups(gs []Group) []Group {
	out := gs[:0:0]
	for _, g := range gs {
		if g.OrgID == "" {
			out = append(out, g)
		}
	}
	return out
}

// ValidateOrgAPIKeyScope is ValidateAPIKey plus a scope check that honors org binding: a GLOBAL
// key with the scope passes everywhere; an ORG-BOUND key passes only for its own org. This is the
// gate to hand an org's SCIM mount:
//
//	scim.NewServer(view, func(t string) bool { return authn.ValidateOrgAPIKeyScope(t, "scim", org.ID) })
func (a *Authenticator) ValidateOrgAPIKeyScope(raw, scope, orgID string) bool {
	info, ok := a.ValidateAPIKey(raw)
	if !ok || !KeyHasScope(info, scope) {
		return false
	}
	return info.OrgID == "" || info.OrgID == orgID
}

// RequireOrgGroupsHTTP is net/http middleware permitting only a session user (gated by GateHTTP)
// who is a LIVE member of their ACTIVE org and belongs to at least one of the named ORG-SCOPED
// groups there. Like RequireOrgHTTP, everything is re-verified against the stores per request —
// org groups never ride in the cookie. Empty names = any live org member. API-key principals are
// refused (org keys authorize surfaces, not group gates).
func (a *Authenticator) RequireOrgGroupsHTTP(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			od := a.orgDir()
			if !a.OrgsEnabled() || od == nil {
				writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "organization groups not available"})
				return
			}
			sc, _ := r.Context().Value(sessionCtxKey).(*SessionClaims)
			if sc == nil || sc.Org == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: no active organization"})
				return
			}
			// Same live-membership gate as RequireOrgHTTP (shared liveOrgMember), plus the org-group
			// check — org groups never ride in the cookie, so both are re-read per request.
			u, _, err := a.liveOrgMember(sc)
			switch {
			case errors.Is(err, ErrNotOrgMember), errors.Is(err, ErrNoOrg), errors.Is(err, ErrNoUser):
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: not a member of this organization"})
				return
			case err != nil:
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "organization check failed"})
				return
			}
			if len(groups) > 0 {
				gs, gerr := od.UserOrgGroups(sc.Org, u.ID)
				if gerr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "organization check failed"})
					return
				}
				if !hasAnyGroup(groupNames(gs), groups) {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: requires organization group membership"})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- the org-scoped directory view (per-customer SCIM) ---

// errOrgView is returned by view methods a per-org caller must never reach (bans, API keys).
var errOrgView = errors.New("authx: not available through an org-scoped directory view")

// ErrOrgOwnerDeprovision is returned by an org-scoped directory when a customer IdP tries to
// deprovision an org OWNER via SCIM. Exported so the SCIM server can render it as a 403 policy
// refusal instead of a 500 (a 5xx an IdP would retry forever) — owners are managed in-app.
var ErrOrgOwnerDeprovision = errors.New("authx: cannot deprovision an organization owner via SCIM — manage owners in-app")

// orgScopedDir presents ONE organization as a complete DirectoryStore, for mounting a per-customer
// SCIM server. Every operation is confined to the org: users are its members, groups are its
// org-scoped groups, and the trust boundary is enforced here (see each method).
type orgScopedDir struct {
	dir   DirectoryStore
	od    OrgDirectoryStore
	orgs  OrgStore
	orgID string
}

// NewOrgScopedDirectory wraps a DirectoryStore in a view confined to orgID, satisfying
// scim.NewServer so each customer's IdP provisions ONLY its own organization:
//
//	view, _ := authx.NewOrgScopedDirectory(store, store, org.ID)
//	scim.NewServer(view, func(t string) bool { return authn.ValidateOrgAPIKeyScope(t, "scim", org.ID) })
//
// Org-scoped semantics differ from the global SCIM mount in three deliberate ways:
//   - Provisioned subjects are NAMESPACED per org ("scim:org<id>:<userName>"), so the same
//     userName pushed by two customers yields two accounts, not one shared identity.
//   - An existing account whose email a customer's IdP asserts is NEVER adopted or rebound
//     (ErrEmailConflict → SCIM 409): users stay global, and bringing an existing account into an
//     org requires the consent-based invite flow. Only accounts this org's IdP provisioned (or
//     that already belong to the org) can be updated through the view.
//   - Deprovisioning (SCIM active=false / DELETE) removes the user FROM THE ORG (membership +
//     its org groups via the RemoveOrgMember contract) — never the global account, which may
//     belong to other orgs. Org owners cannot be deprovisioned via SCIM (manage owners in-app).
func NewOrgScopedDirectory(dir DirectoryStore, orgs OrgStore, orgID string) (DirectoryStore, error) {
	if dir == nil || orgs == nil {
		return nil, errors.New("authx: org-scoped directory requires a DirectoryStore and an OrgStore")
	}
	od, ok := dir.(OrgDirectoryStore)
	if !ok {
		return nil, errors.New("authx: the DirectoryStore does not implement OrgDirectoryStore (org-scoped groups/keys)")
	}
	if _, err := orgs.OrgByID(orgID); err != nil {
		return nil, err
	}
	return &orgScopedDir{dir: dir, od: od, orgs: orgs, orgID: orgID}, nil
}

// orgSubPrefix is the subject namespace for accounts THIS org's IdP provisions.
func (v *orgScopedDir) orgSubPrefix() string { return "scim:org" + v.orgID + ":" }

// nsSub namespaces a SCIM-minted subject ("scim:<userName>") into this org's namespace so identical
// userNames from different customer IdPs can never resolve to one account. An already-namespaced
// sub passes through; a non-SCIM sub (a "local:"/OIDC subject) is returned unchanged — those
// identify globally-owned accounts the view refuses to rebind (see UpsertExternalUser).
func (v *orgScopedDir) nsSub(sub string) string {
	prefix := v.orgSubPrefix()
	if strings.HasPrefix(sub, prefix) {
		return sub
	}
	if rest, ok := strings.CutPrefix(sub, "scim:"); ok {
		return prefix + rest
	}
	return sub
}

// memberRole returns the target's role in the view's org, ErrNotOrgMember when absent.
func (v *orgScopedDir) memberRole(userID string) (string, error) {
	return v.orgs.OrgRole(v.orgID, userID)
}

func (v *orgScopedDir) isMember(userID string) bool {
	_, err := v.memberRole(userID)
	return err == nil
}

// ensureMember adds the user as a plain member if absent — NEVER touching an existing membership,
// so a SCIM re-provision can't demote a role granted in-app (owner stays owner).
func (v *orgScopedDir) ensureMember(userID string) error {
	_, err := v.memberRole(userID)
	if errors.Is(err, ErrNotOrgMember) {
		return v.orgs.SetOrgMember(v.orgID, userID, OrgRoleMember)
	}
	return err
}

// --- users (org-confined) ---

func (v *orgScopedDir) ListUsers() ([]AuthUser, error) {
	members, err := v.orgs.OrgMembers(v.orgID)
	if err != nil {
		return nil, err
	}
	out := make([]AuthUser, 0, len(members))
	for i := range members {
		out = append(out, members[i].User)
	}
	return out, nil
}

func (v *orgScopedDir) UserByID(id string) (*AuthUser, error) {
	u, err := v.dir.UserByID(id)
	if err != nil {
		return nil, err
	}
	if !v.isMember(u.ID) {
		return nil, ErrNoUser
	}
	return u, nil
}

func (v *orgScopedDir) UserByEmail(email string) (*AuthUser, error) {
	u, err := v.dir.UserByEmail(email)
	if err != nil {
		return nil, err
	}
	if !v.isMember(u.ID) {
		return nil, ErrNoUser
	}
	return u, nil
}

// UpsertExternalUser provisions into THIS org. The cross-tenant trust boundary is the heart of the
// view — the underlying upsert's account-linking rule REBINDS an account's global identity when an
// incoming email is asserted verified (correct for the single trusted enterprise IdP of the global
// mount, an account-takeover vector for a per-customer IdP), so the view enforces two rules:
//
//   - The view may only create/update accounts THIS org's IdP OWNS — those under its subject
//     namespace. A sub that doesn't namespace to this org (an invited member's "local:"/OIDC sub,
//     or an account provisioned by another org) identifies a GLOBAL identity the customer IdP must
//     not touch: rewriting its email would redirect that account's password-reset / magic-link to
//     an attacker-chosen address with no mailbox proof. Such members are managed in-app, not here.
//   - An email already owned by a DIFFERENT account (one not provisioned under this namespace) is
//     refused rather than adopted/rebound — existing users join an org through the invite flow,
//     which proves mailbox control.
//
// Both refusals surface as ErrEmailConflict (SCIM 409).
func (v *orgScopedDir) UpsertExternalUser(sub, email, name string, emailVerified bool) (*AuthUser, error) {
	ns := v.nsSub(sub)
	if !strings.HasPrefix(ns, v.orgSubPrefix()) {
		return nil, ErrEmailConflict // not an account this org's IdP owns — never rebind its identity
	}
	if existing, err := v.dir.UserByEmail(email); err == nil && existing != nil && existing.Sub != ns {
		return nil, ErrEmailConflict
	} else if err != nil && !errors.Is(err, ErrNoUser) {
		return nil, err
	}
	u, err := v.dir.UpsertExternalUser(ns, email, name, emailVerified)
	if err != nil {
		return nil, err
	}
	if err := v.ensureMember(u.ID); err != nil {
		return nil, err
	}
	return u, nil
}

// SetUserDisabled carries the org-scoped deprovision semantics: disabling means "remove from this
// org" (the account stays — it may belong to other orgs), re-enabling a non-member is refused
// (re-provision instead), and owners can't be deprovisioned by a customer IdP.
func (v *orgScopedDir) SetUserDisabled(userID string, disabled bool) error {
	role, err := v.memberRole(userID)
	if errors.Is(err, ErrNotOrgMember) {
		if disabled {
			return nil // already not a member — idempotent deprovision
		}
		return ErrNoUser
	}
	if err != nil {
		return err
	}
	if !disabled {
		return nil // already an active member
	}
	if role == OrgRoleOwner {
		return ErrOrgOwnerDeprovision
	}
	return v.orgs.RemoveOrgMember(v.orgID, userID)
}

func (v *orgScopedDir) SetUserBan(string, bool, *time.Time, string) error { return errOrgView }

// --- groups (org-scoped) ---

func (v *orgScopedDir) CreateGroup(name, description string) (*Group, error) {
	return v.od.CreateOrgGroup(v.orgID, name, description)
}

func (v *orgScopedDir) Groups() ([]Group, error) { return v.od.OrgGroups(v.orgID) }

func (v *orgScopedDir) GroupByName(name string) (*Group, error) {
	return v.od.OrgGroupByName(v.orgID, name)
}

// groupInOrg gates every by-ID group operation on the group actually belonging to this org.
func (v *orgScopedDir) groupInOrg(groupID string) error {
	org, err := v.od.OrgOfGroup(groupID)
	if err != nil {
		return err
	}
	if org != v.orgID {
		return ErrNoGroup // another org's (or a global) group is invisible here
	}
	return nil
}

func (v *orgScopedDir) DeleteGroup(id string) error {
	if err := v.groupInOrg(id); err != nil {
		return err
	}
	return v.dir.DeleteGroup(id)
}

func (v *orgScopedDir) AddUserToGroup(userID, groupID string) error {
	if err := v.groupInOrg(groupID); err != nil {
		return err
	}
	if !v.isMember(userID) {
		return ErrNoUser // an org's IdP may only group its own members
	}
	return v.dir.AddUserToGroup(userID, groupID)
}

func (v *orgScopedDir) RemoveUserFromGroup(userID, groupID string) error {
	if err := v.groupInOrg(groupID); err != nil {
		return err
	}
	return v.dir.RemoveUserFromGroup(userID, groupID)
}

func (v *orgScopedDir) GroupMembers(groupID string) ([]AuthUser, error) {
	if err := v.groupInOrg(groupID); err != nil {
		return nil, err
	}
	return v.dir.GroupMembers(groupID)
}

func (v *orgScopedDir) UserGroups(userID string) ([]Group, error) {
	return v.od.UserOrgGroups(v.orgID, userID)
}

// --- API keys: never reachable through a per-org provisioning view ---

func (v *orgScopedDir) CreateAPIKey(string, []string, []string, string, []byte, *time.Time) (*APIKeyInfo, error) {
	return nil, errOrgView
}
func (v *orgScopedDir) APIKeyByHash([]byte) (*APIKeyInfo, error) { return nil, ErrNoCredential }
func (v *orgScopedDir) ListAPIKeys() ([]APIKeyInfo, error)       { return nil, errOrgView }
func (v *orgScopedDir) RevokeAPIKey(string) error                { return errOrgView }
func (v *orgScopedDir) TouchAPIKey(string) error                 { return errOrgView }
