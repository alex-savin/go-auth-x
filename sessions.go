package authx

import (
	"errors"
	"net/http"
	"time"
)

// errRevokedSession marks a parsed-but-revoked session so the gate treats it as no session at all.
var errRevokedSession = errors.New("authx: session revoked")

// SessionRecord is a server-side record of an issued session, used for revocation and device listing.
// It is written at login and read back for the "your sessions" list; only non-secret metadata.
type SessionRecord struct {
	SID       string    `json:"id"`
	Subject   string    `json:"-"`
	UserID    uint      `json:"-"`
	UserAgent string    `json:"userAgent,omitempty"`
	IP        string    `json:"ip,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Current   bool      `json:"current"` // set by the engine when listing; not persisted
}

// SessionStore is OPTIONAL persistence that layers server-side revocation over the stateless
// signed-cookie default. Wire it with SetSessionStore to enable sign-out-everywhere, per-device
// list/revoke, and ban-revokes-all. Sessions minted before a store is configured carry no SID and are
// simply not tracked (they remain valid until they expire) — enable the store from the start for full
// coverage. It mirrors the pluggable RateLimiter seam: nil = today's pure-stateless behavior.
type SessionStore interface {
	// RecordSession persists a freshly minted session (best-effort; a failure must not block login).
	RecordSession(rec SessionRecord) error
	// IsRevoked reports whether the session with this SID must be rejected. It returns true for an
	// explicitly-revoked session AND for an UNKNOWN sid: because RecordSession runs at mint and rows are
	// only ever tombstoned (never deleted), a missing record means a lost write, and honoring it would
	// leave an un-revocable session. Return (false, err) on a genuine store error so the caller can fail
	// open (a transient outage must not mass-logout). Only sessions with a non-empty SID are checked.
	IsRevoked(sid string) (bool, error)
	RevokeSession(sid string) error
	RevokeAllForUser(subject string) error
	ListSessionsForUser(subject string) ([]SessionRecord, error)
}

// SetSessionStore enables optional server-side session revocation + device listing.
func (a *Authenticator) SetSessionStore(s SessionStore) { a.sessions = s }

// SessionsEnabled reports whether server-side session tracking/revocation is wired.
func (a *Authenticator) SessionsEnabled() bool { return a != nil && a.sessions != nil }

// newSessionID returns a random session id when a store is configured, else "" (stateless default).
func (a *Authenticator) newSessionID() string {
	if a.sessions == nil {
		return ""
	}
	return randToken()
}

// recordSession persists a freshly minted session when a store is configured (best-effort).
func (a *Authenticator) recordSession(r *http.Request, sid, subject string, userID uint, ttl time.Duration) {
	if a.sessions == nil || sid == "" {
		return
	}
	now := time.Now()
	_ = a.sessions.RecordSession(SessionRecord{
		SID: sid, Subject: subject, UserID: userID,
		UserAgent: truncate(r.UserAgent(), 400), IP: a.clientIP(r),
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	})
}

// sessionRevoked reports whether a parsed session has been revoked server-side. Allowed (false) when
// no store is configured, the cookie predates the store (no SID), or the store errors (fail-open on a
// transient store fault, to avoid mass logout on a blip).
func (a *Authenticator) sessionRevoked(sc *SessionClaims) bool {
	if a.sessions == nil || sc == nil || sc.SID == "" {
		return false
	}
	revoked, err := a.sessions.IsRevoked(sc.SID)
	return err == nil && revoked
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SessionList (GET /auth/api/sessions) lists the signed-in user's active sessions, flagging the one
// making this request. Requires a session store.
func (a *Authenticator) SessionList(c *reqCtx) {
	sc := a.sessionOf(c)
	if sc == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	if a.sessions == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "session management not available"})
		return
	}
	recs, err := a.sessions.ListSessionsForUser(sc.Subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not list sessions"})
		return
	}
	out := make([]SessionRecord, 0, len(recs))
	for _, r := range recs {
		r.Current = r.SID == sc.SID
		out = append(out, r)
	}
	c.JSON(http.StatusOK, H{"sessions": out})
}

// SessionRevoke (DELETE /auth/api/sessions/{sid}) revokes one of the user's own sessions. It verifies
// the SID belongs to the caller before revoking, so a user can't revoke another account's session.
func (a *Authenticator) SessionRevoke(c *reqCtx) {
	sc := a.sessionOf(c)
	if sc == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	if a.sessions == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "session management not available"})
		return
	}
	target := c.Param("sid")
	recs, err := a.sessions.ListSessionsForUser(sc.Subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not revoke session"})
		return
	}
	owned := false
	for _, r := range recs {
		if r.SID == target {
			owned = true
			break
		}
	}
	if !owned {
		c.JSON(http.StatusNotFound, H{"error": "no such session"})
		return
	}
	if err := a.sessions.RevokeSession(target); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not revoke session"})
		return
	}
	if target == sc.SID { // revoking the current session is a logout — clear the cookies too
		a.clearCookie(c, sessionCookie)
		a.clearCookie(c, csrfCookie)
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

// SessionRevokeOthers (POST /auth/api/sessions/revoke-others) revokes every session except the current
// one — "sign out my other devices".
func (a *Authenticator) SessionRevokeOthers(c *reqCtx) {
	sc := a.sessionOf(c)
	if sc == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	if a.sessions == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "session management not available"})
		return
	}
	recs, err := a.sessions.ListSessionsForUser(sc.Subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not revoke sessions"})
		return
	}
	revoked := 0
	for _, r := range recs {
		if r.SID == sc.SID {
			continue
		}
		if a.sessions.RevokeSession(r.SID) == nil {
			revoked++
		}
	}
	c.JSON(http.StatusOK, H{"ok": true, "revoked": revoked})
}
