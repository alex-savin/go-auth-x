package authx

import (
	"errors"
	"time"
)

// ErrNoGroup is returned by DirectoryStore lookups when a group doesn't exist.
var ErrNoGroup = errors.New("authx: no such group")

// Group is a named collection of users used for access control.
type Group struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt,omitempty"` // for SCIM meta.lastModified; zero if the store doesn't track it
	// OrgID binds an org-scoped group to its organization ("" = a global group, the default).
	// Names are unique per (org, name). Org-scoped groups are invisible to the global verbs
	// (Groups / GroupByName) and never ride in the session cookie — they are managed through
	// OrgDirectoryStore and checked live by RequireOrgGroupsHTTP.
	OrgID string `json:"orgId,omitempty"`
}

// APIKeyInfo is the non-secret metadata of an API key. The raw key is shown ONCE at creation; only
// its sha256 is stored. Calls made with the key act with the key's Groups for access control, and
// are limited to the key's Scopes (e.g. "admin", "scim"). Scopes are DENY-BY-DEFAULT: an empty list
// grants nothing; grant ["*"] for an unrestricted ("root") key.
type APIKeyInfo struct {
	ID         uint       `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"` // leading chars of the key, for identification in lists
	Groups     []string   `json:"groups"`
	Scopes     []string   `json:"scopes,omitempty"` // deny-by-default; e.g. ["scim"], ["admin"], ["*"]
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// OrgID binds the key to one organization ("" = a global key, the default). An org-bound key
	// is refused by every GLOBAL surface — adminGuard, ValidateAPIKeyScope, group merging — and
	// only satisfies ValidateOrgAPIKeyScope for its own org (e.g. that org's SCIM mount).
	OrgID string `json:"orgId,omitempty"`
}

// KeyHasScope reports whether an API key may use a given scope. Least privilege: an EMPTY Scopes
// list grants NOTHING. "*" grants everything; otherwise the scope must be listed explicitly.
func KeyHasScope(info *APIKeyInfo, scope string) bool {
	if info == nil {
		return false
	}
	for _, s := range info.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// DirectoryStore is the OPTIONAL persistence for groups, group membership, API keys, and admin
// user management. Wire it with SetDirectoryStore to enable groups, per-group access control
// (RequireGroups), API-key auth, and the admin REST API. It is intentionally separate from
// CredentialStore, so consumers that only need authentication don't have to implement it.
type DirectoryStore interface {
	// Groups
	CreateGroup(name, description string) (*Group, error)
	Groups() ([]Group, error)
	GroupByName(name string) (*Group, error) // ErrNoGroup if absent
	DeleteGroup(id uint) error
	AddUserToGroup(userID, groupID uint) error
	RemoveUserFromGroup(userID, groupID uint) error
	UserGroups(userID uint) ([]Group, error)
	GroupMembers(groupID uint) ([]AuthUser, error)

	// Admin user management
	ListUsers() ([]AuthUser, error)
	UserByID(id uint) (*AuthUser, error)         // ErrNoUser if absent
	UserByEmail(email string) (*AuthUser, error) // ErrNoUser if absent — used by SCIM to enforce create-uniqueness
	SetUserDisabled(userID uint, disabled bool) error
	// SetUserBan sets or clears a time-boxed ban with a reason. banned=false clears it; a nil `until`
	// with banned=true is a permanent ban, else the ban lifts at *until.
	SetUserBan(userID uint, banned bool, until *time.Time, reason string) error

	// UpsertExternalUser provisions/updates a user from an external directory (LDAP/SCIM) keyed by
	// an external Sub (e.g. "ldap:<uid>" / "scim:<id>"). Applies the same safe email-linking rule.
	UpsertExternalUser(sub, email, name string, emailVerified bool) (*AuthUser, error)

	// API keys (sha256-at-rest). APIKeyByHash returns ErrNoCredential if absent and does NOT
	// itself check expiry (the caller does, so an expired key can still be listed/revoked).
	CreateAPIKey(name string, groups, scopes []string, prefix string, hash []byte, expiresAt *time.Time) (*APIKeyInfo, error)
	APIKeyByHash(hash []byte) (*APIKeyInfo, error)
	ListAPIKeys() ([]APIKeyInfo, error)
	RevokeAPIKey(id uint) error
	TouchAPIKey(id uint) error // best-effort last-used stamp
}

// SetDirectoryStore enables groups, API keys, per-group access control, and the admin REST API.
func (a *Authenticator) SetDirectoryStore(d DirectoryStore) { a.dir = d }

// DirectoryEnabled reports whether the directory features are wired.
func (a *Authenticator) DirectoryEnabled() bool { return a != nil && a.dir != nil }

// groupNames is a small helper to flatten Groups to their names (for the session + access checks).
func groupNames(gs []Group) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	return out
}

// hasAnyGroup reports whether have intersects want (empty want = allow any authenticated user).
func hasAnyGroup(have, want []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, g := range have {
		set[g] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; ok {
			return true
		}
	}
	return false
}
