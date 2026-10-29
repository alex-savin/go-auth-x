package memory

import (
	"errors"
	"slices"
	"sort"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the in-memory store also satisfies the OAuth provider store.
//
// DEMO / SINGLE-PROCESS ONLY: clients, grants, tokens and signing keys live in maps, so a restart
// forgets every registered client and issued token (and rotates nothing — the provider must re-add
// a signing key). Every read returns a copy; nothing handed out aliases the store's state.
var _ authx.OAuthStore = (*Store)(nil)

// errDuplicateOAuth mirrors gormstore's primary-key violation on a Create with an existing ID.
var errDuplicateOAuth = errors.New("memory: oauth record already exists")

// initOAuthLocked creates the OAuth maps on first use. Caller holds s.mu.
func (s *Store) initOAuthLocked() {
	if s.oauthClients != nil {
		return
	}
	s.oauthClients = map[string]*authx.OAuthClient{}
	s.oauthRequests = map[string]*authx.OAuthAuthRequest{}
	s.oauthGrants = map[string]*authx.OAuthGrant{}
	s.oauthAccess = map[string]*authx.OAuthAccessToken{}
	s.oauthRefresh = map[string]*authx.OAuthRefreshToken{}
}

// --- copy helpers (slices and pointers are cloned so callers never alias stored records) ---

// cloneStrings copies a slice, keeping nil distinct from empty.
func cloneStrings(v []string) []string {
	if v == nil {
		return nil
	}
	out := make([]string, len(v))
	copy(out, v)
	return out
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneClient(c *authx.OAuthClient) *authx.OAuthClient {
	o := *c
	o.RedirectURIs = cloneStrings(c.RedirectURIs)
	o.GrantTypes = cloneStrings(c.GrantTypes)
	return &o
}

func cloneRequest(r *authx.OAuthAuthRequest) *authx.OAuthAuthRequest {
	o := *r
	o.Scopes = cloneStrings(r.Scopes)
	o.Resources = cloneStrings(r.Resources)
	o.Prompt = cloneStrings(r.Prompt)
	return &o
}

func cloneGrant(g *authx.OAuthGrant) *authx.OAuthGrant {
	o := *g
	o.Scopes = cloneStrings(g.Scopes)
	o.Resources = cloneStrings(g.Resources)
	o.RevokedAt = cloneTime(g.RevokedAt)
	return &o
}

func cloneAccess(t *authx.OAuthAccessToken) *authx.OAuthAccessToken {
	o := *t
	o.Scopes = cloneStrings(t.Scopes)
	return &o
}

func cloneRefresh(t *authx.OAuthRefreshToken) *authx.OAuthRefreshToken {
	o := *t
	o.Scopes = cloneStrings(t.Scopes)
	o.UsedAt = cloneTime(t.UsedAt)
	return &o
}

func cloneKey(k *authx.OAuthSigningKey) authx.OAuthSigningKey {
	o := *k
	o.PrivatePEM = append([]byte(nil), k.PrivatePEM...)
	o.RetiredAt = cloneTime(k.RetiredAt)
	return o
}

// --- clients ---

func (s *Store) CreateOAuthClient(c *authx.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	if _, ok := s.oauthClients[c.ID]; ok {
		return errDuplicateOAuth
	}
	s.oauthClients[c.ID] = cloneClient(c)
	return nil
}

func (s *Store) OAuthClient(id string) (*authx.OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	c, ok := s.oauthClients[id]
	if !ok {
		return nil, authx.ErrOAuthNotFound
	}
	return cloneClient(c), nil
}

func (s *Store) TouchOAuthClient(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	c, ok := s.oauthClients[id]
	if !ok {
		return authx.ErrOAuthNotFound
	}
	c.LastUsedAt = at
	return nil
}

// DeleteOAuthClient removes the client with its auth requests, grants and tokens (idempotent).
func (s *Store) DeleteOAuthClient(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	s.deleteClientLocked(id)
	return nil
}

// deleteClientLocked drops a client and everything issued to it. Caller holds s.mu.
func (s *Store) deleteClientLocked(id string) {
	delete(s.oauthClients, id)
	for k, r := range s.oauthRequests {
		if r.ClientID == id {
			delete(s.oauthRequests, k)
		}
	}
	for k, g := range s.oauthGrants {
		if g.ClientID == id {
			s.deleteGrantLocked(k)
		}
	}
	for k, t := range s.oauthAccess {
		if t.ClientID == id {
			delete(s.oauthAccess, k)
		}
	}
	for k, t := range s.oauthRefresh {
		if t.ClientID == id {
			delete(s.oauthRefresh, k)
		}
	}
}

// --- authorization requests ---

func (s *Store) SaveOAuthAuthRequest(r *authx.OAuthAuthRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	s.oauthRequests[r.ID] = cloneRequest(r)
	return nil
}

func (s *Store) OAuthAuthRequest(id string) (*authx.OAuthAuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	r, ok := s.oauthRequests[id]
	if !ok {
		return nil, authx.ErrOAuthNotFound
	}
	return cloneRequest(r), nil
}

func (s *Store) OAuthAuthRequestByCode(codeHash string) (*authx.OAuthAuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	if codeHash == "" { // a request with no code issued yet must never match
		return nil, authx.ErrOAuthNotFound
	}
	for _, r := range s.oauthRequests {
		if r.CodeHash == codeHash {
			return cloneRequest(r), nil
		}
	}
	return nil, authx.ErrOAuthNotFound
}

func (s *Store) DeleteOAuthAuthRequest(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	delete(s.oauthRequests, id)
	return nil
}

// --- grants ---

func (s *Store) CreateOAuthGrant(g *authx.OAuthGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	if _, ok := s.oauthGrants[g.ID]; ok {
		return errDuplicateOAuth
	}
	s.oauthGrants[g.ID] = cloneGrant(g)
	return nil
}

func (s *Store) OAuthGrant(id string) (*authx.OAuthGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	g, ok := s.oauthGrants[id]
	if !ok {
		return nil, authx.ErrOAuthNotFound
	}
	return cloneGrant(g), nil
}

func (s *Store) RevokeOAuthGrants(f authx.OAuthGrantFilter, at time.Time) (int, error) {
	if f.Empty() {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	n := 0
	for _, g := range s.oauthGrants {
		if g.RevokedAt != nil ||
			(f.ID != "" && g.ID != f.ID) || (f.Ref != "" && g.Ref != f.Ref) ||
			(f.ClientID != "" && g.ClientID != f.ClientID) || (f.Subject != "" && g.Subject != f.Subject) {
			continue
		}
		t := at
		g.RevokedAt = &t
		n++
	}
	return n, nil
}

// deleteGrantLocked drops a grant and its tokens. Caller holds s.mu.
func (s *Store) deleteGrantLocked(id string) {
	delete(s.oauthGrants, id)
	for k, t := range s.oauthAccess {
		if t.GrantID == id {
			delete(s.oauthAccess, k)
		}
	}
	for k, t := range s.oauthRefresh {
		if t.GrantID == id {
			delete(s.oauthRefresh, k)
		}
	}
}

// --- access tokens ---

func (s *Store) CreateOAuthAccessToken(t *authx.OAuthAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	if _, ok := s.oauthAccess[t.ID]; ok {
		return errDuplicateOAuth
	}
	s.oauthAccess[t.ID] = cloneAccess(t)
	return nil
}

func (s *Store) OAuthAccessToken(id string) (*authx.OAuthAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	t, ok := s.oauthAccess[id]
	if !ok {
		return nil, authx.ErrOAuthNotFound
	}
	return cloneAccess(t), nil
}

func (s *Store) DeleteOAuthAccessToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	delete(s.oauthAccess, id)
	return nil
}

// --- refresh tokens ---

func (s *Store) CreateOAuthRefreshToken(t *authx.OAuthRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	if _, ok := s.oauthRefresh[t.Hash]; ok {
		return errDuplicateOAuth
	}
	s.oauthRefresh[t.Hash] = cloneRefresh(t)
	return nil
}

func (s *Store) OAuthRefreshToken(hash string) (*authx.OAuthRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	t, ok := s.oauthRefresh[hash]
	if !ok {
		return nil, authx.ErrOAuthNotFound
	}
	return cloneRefresh(t), nil
}

// UseOAuthRefreshToken checks and marks under one lock hold, so of concurrent calls exactly one wins.
func (s *Store) UseOAuthRefreshToken(hash string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	t, ok := s.oauthRefresh[hash]
	if !ok {
		return authx.ErrOAuthNotFound
	}
	if t.UsedAt != nil {
		return authx.ErrOAuthTokenUsed
	}
	u := at
	t.UsedAt = &u
	return nil
}

// --- signing keys ---

// OAuthSigningKeys returns every key, oldest first.
func (s *Store) OAuthSigningKeys() ([]authx.OAuthSigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authx.OAuthSigningKey, 0, len(s.oauthKeys))
	for i := range s.oauthKeys {
		out = append(out, cloneKey(&s.oauthKeys[i]))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// AddOAuthSigningKey adds the key, or replaces the one with k.ID.
func (s *Store) AddOAuthSigningKey(k *authx.OAuthSigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.oauthKeys {
		if s.oauthKeys[i].ID == k.ID {
			s.oauthKeys[i] = cloneKey(k)
			return nil
		}
	}
	s.oauthKeys = append(s.oauthKeys, cloneKey(k))
	return nil
}

// RetireOAuthSigningKey marks the key retired at at. A key already retired keeps its first time,
// so replicas retiring it again don't extend its grace.
func (s *Store) RetireOAuthSigningKey(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.oauthKeys {
		if k := &s.oauthKeys[i]; k.ID == id {
			if k.RetiredAt == nil {
				k.RetiredAt = &at
			}
			return nil
		}
	}
	return authx.ErrOAuthNotFound
}

// DeleteOAuthSigningKey removes the key (idempotent).
func (s *Store) DeleteOAuthSigningKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oauthKeys = slices.DeleteFunc(s.oauthKeys, func(k authx.OAuthSigningKey) bool { return k.ID == id })
	return nil
}

// --- cleanup ---

func (s *Store) DeleteExpiredOAuth(now, requestsBefore, clientsBefore time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initOAuthLocked()
	for id, r := range s.oauthRequests {
		if r.CreatedAt.Before(requestsBefore) {
			delete(s.oauthRequests, id)
		}
	}
	for id, t := range s.oauthAccess {
		if t.ExpiresAt.Before(now) {
			delete(s.oauthAccess, id)
		}
	}
	for h, t := range s.oauthRefresh {
		if t.ExpiresAt.Before(now) {
			delete(s.oauthRefresh, h)
		}
	}
	for id, g := range s.oauthGrants {
		if (g.RevokedAt != nil && g.RevokedAt.Before(now)) || (!g.ExpiresAt.IsZero() && g.ExpiresAt.Before(now)) {
			s.deleteGrantLocked(id)
		}
	}
	for id, c := range s.oauthClients {
		last := c.LastUsedAt
		if last.IsZero() { // never used: age from registration
			last = c.CreatedAt
		}
		if c.Dynamic && last.Before(clientsBefore) {
			s.deleteClientLocked(id)
		}
	}
	return nil
}
