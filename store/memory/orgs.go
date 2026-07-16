package memory

import (
	"sort"
	"strconv"
	"strings"
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
	canonical := orgIDString(n)
	// Everything the org owned dies with it: its groups (and their memberships), its pending
	// invites, and any API keys bound to it. Match on the canonical id (see RemoveOrgMember).
	for gid, g := range s.groups {
		if g.OrgID == canonical {
			delete(s.groups, gid)
			for _, set := range s.memberships {
				delete(set, gid)
			}
		}
	}
	for iid, rec := range s.orgInvites {
		if rec.inv.OrgID == canonical {
			delete(s.orgInvites, iid)
		}
	}
	for kid, k := range s.apikeys {
		if k.info.OrgID == canonical {
			delete(s.apikeys, kid)
		}
	}
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
	n, ok := parseOrgID(orgID)
	if !ok {
		return nil
	}
	if set := s.orgMembers[n]; set != nil {
		delete(set, userID)
	}
	// Org-group membership dies with org membership (the OrgStore contract): a former member must
	// not linger in the org's group lists. Match by parsed id, not raw string, so a non-canonical
	// orgID ("01") can't remove the membership yet orphan the group rows (gormstore normalizes too).
	for gid, g := range s.groups {
		if gn, gok := parseOrgID(g.OrgID); gok && gn == n {
			if set := s.memberships[userID]; set != nil {
				delete(set, gid)
			}
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

// --- org invites (first-class records: listable, revocable, hashed-at-rest) ---

// compile-time proof the in-memory store also supports org-scoped directory resources.
var _ authx.OrgDirectoryStore = (*Store)(nil)

type orgInvite struct {
	inv      authx.OrgInvite
	hash     string
	consumed bool
}

func (s *Store) CreateOrgInvite(orgID, email, role, invitedBy string, tokenHash []byte, expiresAt time.Time) (*authx.OrgInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(orgID)
	if !ok || s.orgs[n] == nil {
		return nil, authx.ErrNoOrg
	}
	// Re-inviting an address REPLACES its pending invite (role/expiry update, no row stacking).
	for iid, rec := range s.orgInvites {
		if rec.inv.OrgID == orgID && rec.inv.Email == email && !rec.consumed {
			delete(s.orgInvites, iid)
		}
	}
	s.inviteSeq++
	rec := &orgInvite{
		inv: authx.OrgInvite{
			ID: s.inviteSeq, OrgID: orgID, Email: email, Role: role, InvitedBy: invitedBy,
			ExpiresAt: expiresAt, CreatedAt: time.Now(),
		},
		hash: string(tokenHash),
	}
	s.orgInvites[rec.inv.ID] = rec
	cp := rec.inv
	return &cp, nil
}

func (s *Store) OrgInvites(orgID string) ([]authx.OrgInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(orgID)
	if !ok || s.orgs[n] == nil {
		return nil, authx.ErrNoOrg
	}
	now := time.Now()
	out := []authx.OrgInvite{}
	for _, rec := range s.orgInvites {
		if rec.inv.OrgID == orgID && !rec.consumed && now.Before(rec.inv.ExpiresAt) {
			out = append(out, rec.inv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) RevokeOrgInvite(orgID string, id uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec := s.orgInvites[id]; rec != nil && rec.inv.OrgID == orgID {
		delete(s.orgInvites, id)
	}
	return nil
}

// findValidInviteLocked resolves an unconsumed, unexpired invite by token hash. Caller holds s.mu.
func (s *Store) findValidInviteLocked(tokenHash []byte) *orgInvite {
	now := time.Now()
	for _, rec := range s.orgInvites {
		if rec.hash == string(tokenHash) && !rec.consumed && now.Before(rec.inv.ExpiresAt) {
			return rec
		}
	}
	return nil
}

func (s *Store) PeekOrgInvite(tokenHash []byte) (*authx.OrgInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.findValidInviteLocked(tokenHash)
	if rec == nil {
		return nil, authx.ErrTokenInvalid
	}
	cp := rec.inv
	return &cp, nil
}

func (s *Store) ConsumeOrgInvite(tokenHash []byte) (*authx.OrgInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.findValidInviteLocked(tokenHash)
	if rec == nil {
		return nil, authx.ErrTokenInvalid
	}
	rec.consumed = true
	cp := rec.inv
	return &cp, nil
}

// --- org-scoped groups (OrgDirectoryStore) ---

func (s *Store) CreateOrgGroup(orgID, name, description string) (*authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(orgID)
	if !ok || s.orgs[n] == nil {
		return nil, authx.ErrNoOrg
	}
	trimmed := strings.TrimSpace(name)
	canonical := orgIDString(n) // store the canonical id so every OrgID comparison is stable
	// Names are unique per (org, name) — a global "engineering" and two orgs' "engineering" coexist.
	for _, g := range s.groups {
		if g.OrgID == canonical && g.Name == trimmed {
			return nil, errDuplicateGroup
		}
	}
	s.groupSeq++
	g := &authx.Group{ID: s.groupSeq, Name: trimmed, Description: description, OrgID: canonical, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.groups[g.ID] = g
	cp := *g
	return &cp, nil
}

func (s *Store) OrgGroups(orgID string) ([]authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []authx.Group{}
	for _, g := range s.groups {
		if g.OrgID == orgID {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) OrgGroupByName(orgID, name string) (*authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	for _, g := range s.groups {
		if g.OrgID == orgID && g.Name == name {
			cp := *g
			return &cp, nil
		}
	}
	return nil, authx.ErrNoGroup
}

func (s *Store) OrgOfGroup(groupID uint) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.groups[groupID]; g != nil {
		return g.OrgID, nil
	}
	return "", authx.ErrNoGroup
}

func (s *Store) UserOrgGroups(orgID string, userID uint) ([]authx.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []authx.Group{}
	for gid := range s.memberships[userID] {
		if g := s.groups[gid]; g != nil && g.OrgID == orgID {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- org-bound API keys (OrgDirectoryStore) ---

func (s *Store) CreateOrgAPIKey(orgID, name string, groups, scopes []string, prefix string, hash []byte, expiresAt *time.Time) (*authx.APIKeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseOrgID(orgID)
	if !ok || s.orgs[n] == nil {
		return nil, authx.ErrNoOrg
	}
	s.apiSeq++
	info := authx.APIKeyInfo{ID: s.apiSeq, Name: name, Prefix: prefix, Groups: groups, Scopes: scopes, ExpiresAt: expiresAt, CreatedAt: time.Now(), OrgID: orgID}
	s.apikeys[info.ID] = &apiKey{info: info, hash: string(hash)}
	cp := info
	return &cp, nil
}

func (s *Store) ListOrgAPIKeys(orgID string) ([]authx.APIKeyInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []authx.APIKeyInfo{}
	for _, k := range s.apikeys {
		if k.info.OrgID == orgID {
			out = append(out, k.info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}
