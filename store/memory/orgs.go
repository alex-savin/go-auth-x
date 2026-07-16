package memory

import (
	"sort"
	"strconv"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the in-memory store also satisfies the org interface.
var _ authx.OrgStore = (*Store)(nil)

// org is the in-memory org record; the public authx.Org.ID is the decimal form of the numeric key
// (the boundary conversion the opaque string ID prescribes — parity with gormstore).
type org struct {
	id                   uint
	slug, name           string
	createdAt, updatedAt time.Time
}

func orgIDString(id uint) string { return strconv.FormatUint(uint64(id), 10) }

// parseOrgID maps an opaque ID back to the numeric key; a malformed/zero ID is simply an ID that
// cannot exist, so callers treat !ok as ErrNoOrg rather than a distinct error.
func parseOrgID(s string) (uint, bool) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint(n), true
}

func (o *org) view() *authx.Org {
	return &authx.Org{ID: orgIDString(o.id), Slug: o.slug, Name: o.name, CreatedAt: o.createdAt, UpdatedAt: o.updatedAt}
}

func (s *Store) CreateOrg(slug, name string) (*authx.Org, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Enforce slug uniqueness (parity with gormstore's uniqueIndex), so a concurrent
	// check-then-create can't leave two orgs with the same slug.
	for _, o := range s.orgs {
		if o.slug == slug {
			return nil, errDuplicateOrg
		}
	}
	s.orgSeq++
	o := &org{id: s.orgSeq, slug: slug, name: name, createdAt: time.Now(), updatedAt: time.Now()}
	s.orgs[o.id] = o
	return o.view(), nil
}

func (s *Store) OrgByID(id string) (*authx.Org, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(id)
	if !ok {
		return nil, authx.ErrNoOrg
	}
	if o := s.orgs[n]; o != nil {
		return o.view(), nil
	}
	return nil, authx.ErrNoOrg
}

func (s *Store) OrgBySlug(slug string) (*authx.Org, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.orgs {
		if o.slug == slug {
			return o.view(), nil
		}
	}
	return nil, authx.ErrNoOrg
}

func (s *Store) Orgs() ([]authx.Org, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authx.Org, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, *o.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (s *Store) RenameOrg(id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(id)
	if !ok {
		return authx.ErrNoOrg
	}
	o := s.orgs[n]
	if o == nil {
		return authx.ErrNoOrg
	}
	o.name = name
	o.updatedAt = time.Now()
	return nil
}

func (s *Store) DeleteOrg(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(id)
	if !ok {
		return nil // idempotent: an ID that can't exist is already gone
	}
	delete(s.orgs, n)
	delete(s.orgMembers, n)
	return nil
}

func (s *Store) SetOrgMember(orgID string, userID uint, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(orgID)
	if !ok || s.orgs[n] == nil {
		return authx.ErrNoOrg
	}
	// Refuse a membership for a nonexistent user — a dangling row would be invisible in
	// OrgMembers yet inherited (role and all) by the future user assigned this ID.
	if s.users[userID] == nil {
		return authx.ErrNoUser
	}
	if s.orgMembers[n] == nil {
		s.orgMembers[n] = map[uint]string{}
	}
	s.orgMembers[n][userID] = role
	return nil
}

func (s *Store) RemoveOrgMember(orgID string, userID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := parseOrgID(orgID); ok {
		if set := s.orgMembers[n]; set != nil {
			delete(set, userID)
		}
	}
	return nil
}

func (s *Store) OrgRole(orgID string, userID uint) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(orgID)
	if !ok || s.orgs[n] == nil {
		return "", authx.ErrNoOrg
	}
	if role, is := s.orgMembers[n][userID]; is {
		return role, nil
	}
	return "", authx.ErrNotOrgMember
}

func (s *Store) UserOrgs(userID uint) ([]authx.UserOrg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []authx.UserOrg
	for oid, members := range s.orgMembers {
		if role, is := members[userID]; is {
			if o := s.orgs[oid]; o != nil {
				out = append(out, authx.UserOrg{Org: *o.view(), Role: role})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Org.Slug < out[j].Org.Slug })
	return out, nil
}

func (s *Store) OrgMembers(orgID string) ([]authx.OrgMember, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(orgID)
	if !ok || s.orgs[n] == nil {
		return nil, authx.ErrNoOrg
	}
	var out []authx.OrgMember
	for uid, role := range s.orgMembers[n] {
		if u := s.users[uid]; u != nil {
			out = append(out, authx.OrgMember{User: *view(u), Role: role})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User.Email < out[j].User.Email })
	return out, nil
}
