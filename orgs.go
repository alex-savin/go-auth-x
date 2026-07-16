package authx

import (
	"errors"
	"net/http"
	"time"
)

// Sentinels returned by an OrgStore.
var (
	// ErrNoOrg is returned by OrgStore lookups when an organization doesn't exist.
	ErrNoOrg = errors.New("authx: no such organization")
	// ErrNotOrgMember is returned by OrgRole when the user has no membership in the org.
	ErrNotOrgMember = errors.New("authx: not a member of this organization")
)

// Reserved org roles. Owner and admin gate the self-service org endpoints (member management,
// invites); stores accept any validOrgRole token, so apps may define additional roles and gate on
// them with RequireOrgHTTP.
const (
	OrgRoleOwner  = "owner"
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// Org is a tenant/organization: a named collection of users with per-org roles, layered ABOVE
// authentication. Users stay global (one account, many orgs) — an org never owns a user, so the
// one-user-per-email invariant and the safe account-linking rule are unaffected.
//
// ID is an opaque string (uuid/ULID-friendly, see roadmap #2); the reference stores use their
// numeric PKs and convert at the boundary. Slug is the unique, URL-safe handle.
type Org struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"` // zero if the store doesn't track it
}

// UserOrg is one of a user's org memberships (org-joined, for the org picker).
type UserOrg struct {
	Org  Org    `json:"org"`
	Role string `json:"role"`
}

// OrgMember is one of an org's members (user-joined, for member lists).
type OrgMember struct {
	User AuthUser `json:"user"`
	Role string   `json:"role"`
}

// OrgStore is the OPTIONAL persistence for organizations and their memberships. Wire it with
// SetOrgStore to enable the org layer: an active-org session claim, org switching, member
// management, email invites, RequireOrgHTTP, and the admin org verbs. Like the other capability
// stores, nil = the feature is off with zero behavior change.
//
// Memberships are keyed by the CredentialStore's user ID, so org features also require a
// CredentialStore (see OrgsEnabled).
type OrgStore interface {
	// Orgs. CreateOrg must enforce slug uniqueness (the handlers pre-check and 409, the store's
	// constraint is the fail-closed backstop under races). DeleteOrg cascades memberships and is
	// idempotent. Lookups return ErrNoOrg when absent.
	CreateOrg(slug, name string) (*Org, error)
	OrgByID(id string) (*Org, error)
	OrgBySlug(slug string) (*Org, error)
	Orgs() ([]Org, error)
	RenameOrg(id, name string) error
	DeleteOrg(id string) error

	// Membership. SetOrgMember UPSERTS (adds the user or updates their role) — role-change policy
	// (who may grant what, the last-owner guard) is enforced by the callers, not the store. It
	// returns ErrNoOrg when the org is absent and ErrNoUser when the user doesn't exist (a
	// dangling row would be invisible in OrgMembers yet inherited by a future user assigned that
	// ID). RemoveOrgMember is idempotent. OrgRole returns ErrNotOrgMember when there is no
	// membership (ErrNoOrg when the org itself is absent).
	SetOrgMember(orgID string, userID uint, role string) error
	RemoveOrgMember(orgID string, userID uint) error
	OrgRole(orgID string, userID uint) (string, error)
	UserOrgs(userID uint) ([]UserOrg, error)
	OrgMembers(orgID string) ([]OrgMember, error)
}

// SetOrgStore installs the optional organization persistence, enabling the org layer (active-org
// session claim, /auth/org/* + /auth/orgs endpoints, invites, RequireOrgHTTP, admin org verbs).
// Org features also need a CredentialStore — memberships are keyed by its user IDs.
func (a *Authenticator) SetOrgStore(o OrgStore) { a.orgs = o }

// OrgsEnabled reports whether the org layer is active: an OrgStore AND a CredentialStore are wired
// (memberships reference credential-store user IDs, so orgs cannot operate without one).
func (a *Authenticator) OrgsEnabled() bool { return a != nil && a.orgs != nil && a.creds != nil }

// validOrgSlug enforces the URL-safe org handle: 1–63 chars of [a-z0-9-], no leading/trailing
// hyphen (DNS-label-shaped, so a slug can safely appear in paths and subdomains).
func validOrgSlug(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// validOrgRole bounds a role token: 1–32 chars of [a-z0-9_-]. The reserved roles pass; apps may
// use their own tokens. Bounded + charset-limited because roles are embedded in invite-token
// purposes and session claims.
func validOrgRole(r string) bool {
	if len(r) == 0 || len(r) > 32 {
		return false
	}
	for i := 0; i < len(r); i++ {
		c := r[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// orgRoleIsManager reports whether a role may manage the org's members (list is fixed: the
// reserved owner/admin roles; custom roles never manage).
func orgRoleIsManager(role string) bool { return role == OrgRoleOwner || role == OrgRoleAdmin }

// defaultOrgClaims picks the active-org claims stamped on a FRESH session: the user's sole
// membership, or none when the user belongs to zero or several orgs (the app then prompts and
// calls POST /auth/org/switch). Deterministic and conservative — never guesses among multiple.
func (a *Authenticator) defaultOrgClaims(userID uint) (orgID, role string) {
	if a.orgs == nil {
		return "", ""
	}
	ms, err := a.orgs.UserOrgs(userID)
	if err != nil || len(ms) != 1 {
		return "", ""
	}
	return ms[0].Org.ID, ms[0].Role
}

// defaultOrgClaimsForSub is defaultOrgClaims for mint sites that only hold the subject (OIDC
// callback, 2FA completion). Best-effort: any miss yields no active org, never an error.
func (a *Authenticator) defaultOrgClaimsForSub(sub string) (orgID, role string) {
	if !a.OrgsEnabled() {
		return "", ""
	}
	u, err := a.creds.UserBySub(sub)
	if err != nil {
		return "", ""
	}
	return a.defaultOrgClaims(u.ID)
}

// liveOrgRole resolves the LIVE role of the gated session's user in its active org. The cookie
// only names the org — membership and role are re-checked against the store on every call, so a
// removal or demotion takes effect immediately instead of riding out the session TTL (org
// off-boarding is a sharper boundary than the group claims, which stay cookie-stale by design).
func (a *Authenticator) liveOrgRole(sc *SessionClaims) (role string, err error) {
	if sc == nil || sc.Org == "" {
		return "", ErrNotOrgMember
	}
	u, err := a.creds.UserBySub(sc.Subject)
	if err != nil {
		return "", err
	}
	return a.orgs.OrgRole(sc.Org, u.ID)
}

// RequireOrgHTTP is net/http middleware permitting only a session user (gated by GateHTTP) whose
// LIVE role in their ACTIVE org is one of the named roles. Empty roles = any current member.
// Membership is re-verified against the OrgStore per request (one indexed lookup) — see
// liveOrgRole. API-key principals carry no org, so they are refused; org-scoped keys are a later
// phase. NOTE: this gates "who is acting in which org" — row-level isolation of the app's own
// data remains the app's responsibility.
func (a *Authenticator) RequireOrgHTTP(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.OrgsEnabled() {
				writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "organizations not available"})
				return
			}
			sc, _ := r.Context().Value(sessionCtxKey).(*SessionClaims)
			if sc == nil || sc.Org == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: no active organization"})
				return
			}
			role, err := a.liveOrgRole(sc)
			switch {
			case errors.Is(err, ErrNotOrgMember), errors.Is(err, ErrNoOrg), errors.Is(err, ErrNoUser):
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: not a member of this organization"})
				return
			case err != nil:
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "organization check failed"})
				return
			}
			if len(roles) > 0 && !hasAnyGroup([]string{role}, roles) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: requires organization role"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
