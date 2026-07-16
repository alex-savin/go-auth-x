package memory

import (
	"sort"
	"strings"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the in-memory store also satisfies the directory interface.
var _ authx.DirectoryStore = (*Store)(nil)

// --- groups ---

func (s *Store) CreateGroup(name, description string) (*authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Enforce name uniqueness among GLOBAL groups (parity with gormstore's (org, name) index) —
	// org-scoped groups live in per-org namespaces, so only a global/global collision is refused.
	trimmed := strings.TrimSpace(name)
	for _, g := range s.groups {
		if g.OrgID == "" && g.Name == trimmed {
			return nil, errDuplicateGroup
		}
	}
	s.groupSeq++
	gid := s.groupSeq
	g := &authx.Group{ID: idStr(gid), Name: trimmed, Description: description, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.groups[gid] = g
	cp := *g
	return &cp, nil
}

// Groups lists the GLOBAL groups only — org-scoped groups are reached through OrgGroups (see
// OrgDirectoryStore), so an org's namespace never leaks into the global verbs.
func (s *Store) Groups() ([]authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authx.Group, 0, len(s.groups))
	for _, g := range s.groups {
		if g.OrgID == "" {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GroupByName resolves a GLOBAL group; org-scoped names live in their org's namespace
// (OrgGroupByName).
func (s *Store) GroupByName(name string) (*authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	for _, g := range s.groups {
		if g.OrgID == "" && g.Name == name {
			cp := *g
			return &cp, nil
		}
	}
	return nil, authx.ErrNoGroup
}

func (s *Store) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(id)
	if !ok {
		return nil
	}
	delete(s.groups, n)
	for _, set := range s.memberships {
		delete(set, n)
	}
	return nil
}

func (s *Store) AddUserToGroup(userID, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid, uok := parseID(userID)
	gid, gok := parseID(groupID)
	if !uok || !gok {
		return nil // a membership tying a nonexistent user/group can't exist — nothing to add
	}
	if s.memberships[uid] == nil {
		s.memberships[uid] = map[uint]bool{}
	}
	s.memberships[uid][gid] = true
	return nil
}

func (s *Store) RemoveUserFromGroup(userID, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid, uok := parseID(userID)
	gid, gok := parseID(groupID)
	if !uok || !gok {
		return nil
	}
	if set := s.memberships[uid]; set != nil {
		delete(set, gid)
	}
	return nil
}

func (s *Store) UserGroups(userID string) ([]authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil, nil
	}
	var out []authx.Group
	for gid := range s.memberships[n] {
		if g := s.groups[gid]; g != nil {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) GroupMembers(groupID string) ([]authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(groupID)
	if !ok {
		return nil, nil
	}
	var out []authx.AuthUser
	for uid, set := range s.memberships {
		if set[n] {
			if u := s.users[uid]; u != nil {
				out = append(out, *view(u))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

// --- admin user management ---

func (s *Store) ListUsers() ([]authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authx.AuthUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *view(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (s *Store) UserByID(id string) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(id)
	if !ok {
		return nil, authx.ErrNoUser
	}
	if u := s.users[n]; u != nil {
		return view(u), nil
	}
	return nil, authx.ErrNoUser
}

func (s *Store) SetUserDisabled(userID string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	if u := s.users[n]; u != nil {
		u.disabled = disabled
	}
	return nil
}

func (s *Store) SetUserBan(userID string, banned bool, until *time.Time, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	if u := s.users[n]; u != nil {
		u.banned = banned
		if banned {
			u.banReason = reason
			if until != nil {
				u.bannedUntil = *until
			} else {
				u.bannedUntil = time.Time{}
			}
		} else {
			u.banReason = ""
			u.bannedUntil = time.Time{}
		}
	}
	return nil
}

// UpsertExternalUser provisions a directory-sourced user (LDAP/SCIM) via the safe linking rule.
func (s *Store) UpsertExternalUser(sub, email, name string, emailVerified bool) (*authx.AuthUser, error) {
	return s.UpsertUserOnLogin(sub, email, name, emailVerified)
}

// --- api keys ---

func (s *Store) CreateAPIKey(name string, groups, scopes []string, prefix string, hash []byte, expiresAt *time.Time) (*authx.APIKeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiSeq++
	kid := s.apiSeq
	info := authx.APIKeyInfo{ID: idStr(kid), Name: name, Prefix: prefix, Groups: groups, Scopes: scopes, ExpiresAt: expiresAt, CreatedAt: time.Now()}
	s.apikeys[kid] = &apiKey{info: info, hash: string(hash)}
	cp := info
	return &cp, nil
}

func (s *Store) APIKeyByHash(hash []byte) (*authx.APIKeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.apikeys {
		if k.hash == string(hash) {
			cp := k.info
			return &cp, nil
		}
	}
	return nil, authx.ErrNoCredential
}

func (s *Store) ListAPIKeys() ([]authx.APIKeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authx.APIKeyInfo, 0, len(s.apikeys))
	for _, k := range s.apikeys {
		out = append(out, k.info)
	}
	sort.Slice(out, func(i, j int) bool { return idLess(out[j].ID, out[i].ID) })
	return out, nil
}

func (s *Store) RevokeAPIKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(id)
	if !ok {
		return nil
	}
	delete(s.apikeys, n)
	return nil
}

func (s *Store) TouchAPIKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(id)
	if !ok {
		return nil
	}
	if k := s.apikeys[n]; k != nil {
		now := time.Now()
		k.info.LastUsedAt = &now
	}
	return nil
}

// idLess orders two opaque IDs by their underlying numeric key, so listings keep numeric order
// (newest-first / oldest-first) that lexical string sorting would otherwise break ("10" < "9").
func idLess(a, b string) bool {
	an, _ := parseID(a)
	bn, _ := parseID(b)
	return an < bn
}
