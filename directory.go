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
}

// APIKeyInfo is the non-secret metadata of an API key. The raw key is shown ONCE at creation; only
// its sha256 is stored. Calls made with the key act with the key's Groups for access control.
type APIKeyInfo struct {
	ID         uint       `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"` // leading chars of the key, for identification in lists
	Groups     []string   `json:"groups"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
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
	UserByID(id uint) (*AuthUser, error) // ErrNoUser if absent
	SetUserDisabled(userID uint, disabled bool) error

	// UpsertExternalUser provisions/updates a user from an external directory (LDAP/SCIM) keyed by
	// an external Sub (e.g. "ldap:<uid>" / "scim:<id>"). Applies the same safe email-linking rule.
	UpsertExternalUser(sub, email, name string, emailVerified bool) (*AuthUser, error)

	// API keys (sha256-at-rest). APIKeyByHash returns ErrNoCredential if absent and does NOT
	// itself check expiry (the caller does, so an expired key can still be listed/revoked).
	CreateAPIKey(name string, groups []string, prefix string, hash []byte, expiresAt *time.Time) (*APIKeyInfo, error)
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
