package memory

import (
	"sort"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the in-memory store also satisfies the optional session store.
//
// DEMO / SINGLE-PROCESS ONLY: the session records live in a map with no persistence, so a process
// restart empties it — and because IsRevoked fails closed on an unknown SID, that logs EVERY outstanding
// user out on each restart/deploy. Use gormstore (or another durable SessionStore) for anything that
// restarts or scales. Expired rows are pruned opportunistically on write to bound growth.
var _ authx.SessionStore = (*Store)(nil)

func (s *Store) RecordSession(rec authx.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneSessionsLocked() // bound growth — an expired session's cookie is already invalid (exp), so dropping the row is safe
	s.sessions[rec.SID] = &sessionRec{rec: rec}
	return nil
}

// pruneSessionsLocked drops expired session rows. Caller holds s.mu. Safe because a row past ExpiresAt
// corresponds to a cookie that parseSession already rejects on `exp`, so it can never reach IsRevoked.
func (s *Store) pruneSessionsLocked() {
	now := time.Now()
	for sid, r := range s.sessions {
		if r.rec.ExpiresAt.Before(now) {
			delete(s.sessions, sid)
		}
	}
}

func (s *Store) IsRevoked(sid string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.sessions[sid]; r != nil {
		return r.revoked, nil
	}
	// Unknown non-empty SID → fail closed: a recorded session is only ever tombstoned, never deleted, so
	// a missing record means a lost RecordSession write, not a legitimately untracked session.
	return true, nil
}

func (s *Store) RevokeSession(sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.sessions[sid]; r != nil {
		r.revoked = true
	}
	return nil
}

func (s *Store) RevokeAllForUser(subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.sessions {
		if r.rec.Subject == subject {
			r.revoked = true
		}
	}
	return nil
}

func (s *Store) ListSessionsForUser(subject string) ([]authx.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []authx.SessionRecord
	for _, r := range s.sessions {
		if r.rec.Subject == subject && !r.revoked && r.rec.ExpiresAt.After(now) {
			out = append(out, r.rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
