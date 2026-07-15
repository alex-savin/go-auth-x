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
	// Enforce name uniqueness (parity with gormstore's uniqueIndex on Group.Name), so a concurrent
	// check-then-create can't leave two groups with the same name.
	trimmed := strings.TrimSpace(name)
	for _, g := range s.groups {
		if g.Name == trimmed {
			return nil, errDuplicateGroup
		}
	}
	s.groupSeq++
	g := &authx.Group{ID: s.groupSeq, Name: strings.TrimSpace(name), Description: description, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.groups[g.ID] = g
	cp := *g
	return &cp, nil
}

func (s *Store) Groups() ([]authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authx.Group, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) GroupByName(name string) (*authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	for _, g := range s.groups {
		if g.Name == name {
			cp := *g
			return &cp, nil
		}
	}
	return nil, authx.ErrNoGroup
}

func (s *Store) DeleteGroup(id uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groups, id)
	for _, set := range s.memberships {
		delete(set, id)
	}
	return nil
}

func (s *Store) AddUserToGroup(userID, groupID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.memberships[userID] == nil {
		s.memberships[userID] = map[uint]bool{}
	}
	s.memberships[userID][groupID] = true
	return nil
}

func (s *Store) RemoveUserFromGroup(userID, groupID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.memberships[userID]; set != nil {
		delete(set, groupID)
	}
	return nil
}

func (s *Store) UserGroups(userID uint) ([]authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []authx.Group
	for gid := range s.memberships[userID] {
		if g := s.groups[gid]; g != nil {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) GroupMembers(groupID uint) ([]authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []authx.AuthUser
	for uid, set := range s.memberships {
		if set[groupID] {
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

func (s *Store) UserByID(id uint) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[id]; u != nil {
		return view(u), nil
	}
	return nil, authx.ErrNoUser
}

func (s *Store) SetUserDisabled(userID uint, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[userID]; u != nil {
		u.disabled = disabled
	}
	return nil
}

func (s *Store) SetUserBan(userID uint, banned bool, until *time.Time, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[userID]; u != nil {
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
	info := authx.APIKeyInfo{ID: s.apiSeq, Name: name, Prefix: prefix, Groups: groups, Scopes: scopes, ExpiresAt: expiresAt, CreatedAt: time.Now()}
	s.apikeys[info.ID] = &apiKey{info: info, hash: string(hash)}
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
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func (s *Store) RevokeAPIKey(id uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.apikeys, id)
	return nil
}

func (s *Store) TouchAPIKey(id uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k := s.apikeys[id]; k != nil {
		now := time.Now()
		k.info.LastUsedAt = &now
	}
	return nil
}
