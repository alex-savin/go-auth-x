// Package memory is a zero-dependency, in-memory reference implementation of
// authx.CredentialStore (+ the safe verified-email linking rule). It's intended for tests,
// demos, and single-process deployments; state is lost on restart and not shared across
// replicas. For production use gormstore.
package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

type user struct {
	id                   uint
	sub                  string
	email, name          string
	emailVerified        bool
	disabled             bool
	webauthnHandle       []byte
	createdAt, updatedAt time.Time
}

type passkey struct {
	p      authx.Passkey
	userID uint
}

type token struct {
	purpose    string
	userID     uint
	email      string
	hash       []byte
	expiresAt  time.Time
	consumedAt *time.Time
}

type audit struct {
	email     string
	success   bool
	createdAt time.Time
}

// Store is an in-memory CredentialStore.
type Store struct {
	mu        sync.Mutex
	seq       uint
	users     map[uint]*user
	passwords map[uint]struct{ hash, algo string }
	passkeys  map[uint]*passkey // keyed by passkey id
	pkSeq     uint
	oauth     map[string]uint // (provider|subject) -> userID
	tokens    []*token
	audits    []*audit
	// directory state
	groups      map[uint]*authx.Group
	groupSeq    uint
	memberships map[uint]map[uint]bool // userID -> set of groupID
	apikeys     map[uint]*apiKey
	apiSeq      uint
	// 2fa state
	totp     map[uint]*totpRec
	recovery map[uint]map[string]bool // userID -> set of hex(sha256(code))
}

type totpRec struct {
	secret   string
	enabled  bool
	lastStep uint64
}

type apiKey struct {
	info authx.APIKeyInfo
	hash string
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		users:       map[uint]*user{},
		passwords:   map[uint]struct{ hash, algo string }{},
		passkeys:    map[uint]*passkey{},
		oauth:       map[string]uint{},
		groups:      map[uint]*authx.Group{},
		memberships: map[uint]map[uint]bool{},
		apikeys:     map[uint]*apiKey{},
		totp:        map[uint]*totpRec{},
		recovery:    map[uint]map[string]bool{},
	}
}

func norm(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func view(u *user) *authx.AuthUser {
	return &authx.AuthUser{ID: u.id, Sub: u.sub, Email: u.email, Name: u.name, EmailVerified: u.emailVerified, Disabled: u.disabled, CreatedAt: u.createdAt, UpdatedAt: u.updatedAt}
}

func (s *Store) findByEmail(email string) *user {
	email = norm(email)
	for _, u := range s.users {
		if u.email == email {
			return u
		}
	}
	return nil
}

func (s *Store) findBySub(sub string) *user {
	for _, u := range s.users {
		if u.sub == sub {
			return u
		}
	}
	return nil
}

func (s *Store) UserByEmail(email string) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.findByEmail(email); u != nil {
		return view(u), nil
	}
	return nil, authx.ErrNoUser
}

func (s *Store) UserBySub(sub string) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.findBySub(sub); u != nil {
		return view(u), nil
	}
	return nil, authx.ErrNoUser
}

func (s *Store) CreateLocalUser(email, name string) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findByEmail(email) != nil {
		return nil, authx.ErrEmailConflict
	}
	s.seq++
	now := time.Now()
	u := &user{id: s.seq, sub: "local:" + randID(), email: norm(email), name: name, createdAt: now, updatedAt: now}
	s.users[u.id] = u
	return view(u), nil
}

func (s *Store) SetEmailVerified(userID uint, verified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.users[userID]; u != nil {
		u.emailVerified = verified
		u.updatedAt = time.Now()
	}
	return nil
}

func (s *Store) EnsureWebauthnHandle(userID uint) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[userID]
	if u == nil {
		return nil, authx.ErrNoUser
	}
	if len(u.webauthnHandle) == 0 {
		h := make([]byte, 32)
		_, _ = rand.Read(h)
		u.webauthnHandle = h
	}
	return u.webauthnHandle, nil
}

func (s *Store) UserByWebauthnHandle(handle []byte) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if string(u.webauthnHandle) == string(handle) {
			return view(u), nil
		}
	}
	return nil, authx.ErrNoUser
}

func (s *Store) Passkeys(userID uint) ([]authx.Passkey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []authx.Passkey
	for _, pk := range s.passkeys {
		if pk.userID == userID {
			out = append(out, pk.p)
		}
	}
	return out, nil
}

func (s *Store) AddPasskey(userID uint, p authx.Passkey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkSeq++
	p.ID = s.pkSeq
	p.CreatedAt, p.LastUsedAt = time.Now(), time.Now()
	s.passkeys[p.ID] = &passkey{p: p, userID: userID}
	return nil
}

func (s *Store) TouchPasskey(credentialID []byte, signCount uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pk := range s.passkeys {
		if string(pk.p.CredentialID) == string(credentialID) {
			if signCount > pk.p.SignCount { // sign counts are monotonic — never let a stale/replayed assertion regress it
				pk.p.SignCount = signCount
			}
			pk.p.LastUsedAt = time.Now()
		}
	}
	return nil
}

func (s *Store) RemovePasskey(userID, id uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pk := s.passkeys[id]; pk != nil && pk.userID == userID {
		delete(s.passkeys, id)
	}
	return nil
}

func (s *Store) PasswordHash(userID uint) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pc, ok := s.passwords[userID]; ok {
		return pc.hash, pc.algo, nil
	}
	return "", "", authx.ErrNoCredential
}

func (s *Store) SetPasswordHash(userID uint, hash, algo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwords[userID] = struct{ hash, algo string }{hash, algo}
	return nil
}

func (s *Store) UserByOAuth(provider, subject string) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if uid, ok := s.oauth[provider+"|"+subject]; ok {
		if u := s.users[uid]; u != nil {
			return view(u), nil
		}
	}
	return nil, authx.ErrNoUser
}

func (s *Store) LinkOAuth(userID uint, provider, subject, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.oauth[provider+"|"+subject]; !exists {
		s.oauth[provider+"|"+subject] = userID
	}
	return nil
}

func (s *Store) CreateToken(purpose string, userID uint, email string, tokenHash []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, &token{purpose: purpose, userID: userID, email: norm(email), hash: tokenHash, expiresAt: expiresAt})
	return nil
}

func (s *Store) ConsumeToken(purpose string, tokenHash []byte) (*authx.TokenClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.purpose == purpose && string(t.hash) == string(tokenHash) {
			if t.consumedAt != nil || time.Now().After(t.expiresAt) {
				return nil, authx.ErrTokenInvalid
			}
			now := time.Now()
			t.consumedAt = &now
			return &authx.TokenClaim{UserID: t.userID, Email: t.email}, nil
		}
	}
	return nil, authx.ErrTokenInvalid
}

func (s *Store) RecordAudit(userID uint, email, ip, method, event string, success bool, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits = append(s.audits, &audit{email: norm(email), success: success, createdAt: time.Now()})
}

func (s *Store) RecentFailures(email string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.audits {
		if a.email == norm(email) && !a.success && !a.createdAt.Before(since) {
			n++
		}
	}
	return n, nil
}

// Authorizer returns an authx.Authorizer that upserts identities with the safe linking rule.
func (s *Store) Authorizer() authx.Authorizer { return &authorizer{s} }

type authorizer struct{ s *Store }

func (a *authorizer) Authorize(_ context.Context, id authx.Identity) (string, error) {
	_, err := a.s.UpsertUserOnLogin(id.Subject, id.Email, id.Name, id.EmailVerified)
	return "", err
}

// UpsertUserOnLogin applies the same safe account-linking rule as gormstore: adopt an existing
// email row only if it's a bootstrap placeholder or already verified; an unverified, non-bootstrap
// squatter yields ErrEmailConflict (no takeover).
func (s *Store) UpsertUserOnLogin(sub, email, name string, emailVerified bool) (*authx.AuthUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	email = norm(email)
	if u := s.findBySub(sub); u != nil {
		// Uphold the one-user-per-email invariant gormstore enforces with a unique index: refuse to
		// move this row onto an email another row already owns.
		if email != u.email {
			if other := s.findByEmail(email); other != nil && other.id != u.id {
				return nil, authx.ErrEmailConflict
			}
		}
		u.email, u.name = email, name
		if emailVerified {
			u.emailVerified = true
		}
		return view(u), nil
	}
	if existing := s.findByEmail(email); existing != nil {
		bootstrap := strings.HasPrefix(existing.sub, "bootstrap:")
		if bootstrap || existing.emailVerified {
			// Rebind a verified row to a new subject only when THIS login proved the email; an
			// unproven login must not seize a verified account. Bootstrap rows are operator-seeded
			// and safe to claim on first login. (Mirrors gormstore.)
			if !bootstrap && !emailVerified {
				return nil, authx.ErrEmailConflict
			}
			existing.sub, existing.name = sub, name
			if emailVerified {
				existing.emailVerified = true
			}
			return view(existing), nil
		}
		// Unverified, non-bootstrap squatter: a verified incoming login reclaims the email
		// (delete the squatter + its credentials); an unproven one is refused.
		if !emailVerified {
			return nil, authx.ErrEmailConflict
		}
		s.deleteUserCascadeLocked(existing.id)
	}
	s.seq++
	u := &user{id: s.seq, sub: sub, email: email, name: name, emailVerified: emailVerified, createdAt: time.Now(), updatedAt: time.Now()}
	s.users[u.id] = u
	return view(u), nil
}

// deleteUserCascadeLocked removes a user + everything keyed to it. Caller holds s.mu.
func (s *Store) deleteUserCascadeLocked(id uint) {
	delete(s.users, id)
	delete(s.passwords, id)
	delete(s.memberships, id)
	delete(s.totp, id)
	delete(s.recovery, id)
	for pkid, pk := range s.passkeys {
		if pk.userID == id {
			delete(s.passkeys, pkid)
		}
	}
	for k, uid := range s.oauth {
		if uid == id {
			delete(s.oauth, k)
		}
	}
	kept := s.tokens[:0]
	for _, t := range s.tokens {
		if t.userID != id {
			kept = append(kept, t)
		}
	}
	s.tokens = kept
}
