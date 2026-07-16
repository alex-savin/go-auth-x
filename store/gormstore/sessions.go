package gormstore

import (
	"errors"
	"time"

	"gorm.io/gorm"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the GORM store also satisfies the optional session store.
var _ authx.SessionStore = (*Store)(nil)

// Session records an issued session for server-side revocation + device listing. RevokedAt non-nil
// means the session was revoked. Rows are RETAINED (never auto-deleted) — revocation relies on the
// tombstone surviving, so IsRevoked keeps denying a revoked/deleted user until the cookie would expire.
// Listing filters out expired + revoked rows; prune expired rows out-of-band (a periodic
// DELETE ... WHERE expires_at < now) if the table's growth matters for your retention.
type Session struct {
	SID       string `gorm:"column:sid;primaryKey"`
	Sub       string `gorm:"index"`
	UserID    uint   `gorm:"index"`
	UserAgent string
	IP        string
	CreatedAt time.Time
	ExpiresAt time.Time `gorm:"index"`
	RevokedAt *time.Time
}

func (Session) TableName() string { return "authx_sessions" }

// migrateSessions is called by New to migrate the session table.
func (s *Store) migrateSessions() error { return s.db.AutoMigrate(&Session{}) }

func (s *Store) RecordSession(rec authx.SessionRecord) error {
	// UserID is stored data, not a query key: "" (a session not tied to a stored user) and any
	// unparseable ID record no linkage (user_id 0), while SID-keyed revocation still works.
	uid, _ := userPK(rec.UserID)
	return s.db.Create(&Session{
		SID: rec.SID, Sub: rec.Subject, UserID: uid,
		UserAgent: rec.UserAgent, IP: rec.IP,
		CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	}).Error
}

func (s *Store) IsRevoked(sid string) (bool, error) {
	var row Session
	if err := s.db.Where("sid = ?", sid).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// A session with a non-empty SID is recorded at mint and only ever TOMBSTONED (never
			// deleted), so a missing row means the record was never durably written (a lost RecordSession)
			// — fail closed rather than honor an untracked, un-revocable session. (Pre-store sessions carry
			// an empty SID and never reach here — see sessionRevoked.)
			return true, nil
		}
		return false, err // a real store error: the caller fails open (avoid mass logout on a blip)
	}
	return row.RevokedAt != nil, nil
}

func (s *Store) RevokeSession(sid string) error {
	now := time.Now()
	return s.db.Model(&Session{}).Where("sid = ? AND revoked_at IS NULL", sid).
		Update("revoked_at", now).Error
}

func (s *Store) RevokeAllForUser(subject string) error {
	now := time.Now()
	return s.db.Model(&Session{}).Where("sub = ? AND revoked_at IS NULL", subject).
		Update("revoked_at", now).Error
}

func (s *Store) ListSessionsForUser(subject string) ([]authx.SessionRecord, error) {
	var rows []Session
	err := s.db.Where("sub = ? AND revoked_at IS NULL AND expires_at > ?", subject, time.Now()).
		Order("created_at desc").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]authx.SessionRecord, 0, len(rows))
	for i := range rows {
		out = append(out, authx.SessionRecord{
			SID: rows[i].SID, Subject: rows[i].Sub, UserID: userIDStr(rows[i].UserID),
			UserAgent: rows[i].UserAgent, IP: rows[i].IP,
			CreatedAt: rows[i].CreatedAt, ExpiresAt: rows[i].ExpiresAt,
		})
	}
	return out, nil
}
