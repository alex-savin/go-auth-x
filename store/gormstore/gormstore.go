// Package gormstore is a reference GORM-backed implementation of authx.CredentialStore plus a
// safe reference Authorizer (identity upsert with verified-email account-linking). It is
// self-contained: all tables are prefixed authx_ and migrated by New, so it drops into any
// Postgres/SQLite GORM app without colliding with existing tables.
package gormstore

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	authx "github.com/alex-savin/go-auth-x"
)

// --- models (self-contained, authx_-prefixed) ---

// User is the opaque principal. Sub is the join key everywhere: the OIDC subject for IdP
// logins, or "local:<uuid>" for in-app credentials.
type User struct {
	ID             uint       `gorm:"primaryKey"`
	Sub            string     `gorm:"uniqueIndex"`
	Email          string     `gorm:"index"`
	Name           string     `gorm:""`
	EmailVerified  bool       `gorm:""`
	WebauthnHandle []byte     `gorm:""`
	Disabled       bool       `gorm:""`
	Banned         bool       `gorm:""`
	BannedUntil    *time.Time `gorm:""` // nil = permanent when Banned, or unused when !Banned
	BanReason      string     `gorm:""`
	CreatedAt      time.Time  `gorm:""`
	UpdatedAt      time.Time  `gorm:""` // gorm auto-updates on save; surfaced as SCIM meta.lastModified
	LastLoginAt    time.Time  `gorm:""`
}

func (User) TableName() string { return "authx_users" }

type PasswordCredential struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"uniqueIndex"`
	Hash      string `gorm:""`
	Algo      string `gorm:""`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (PasswordCredential) TableName() string { return "authx_password_credentials" }

type WebauthnCredential struct {
	ID              uint   `gorm:"primaryKey"`
	UserID          uint   `gorm:"index"`
	CredentialID    []byte `gorm:"uniqueIndex"`
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	Transports      string
	BackupEligible  bool
	BackupState     bool
	Name            string
	CreatedAt       time.Time
	LastUsedAt      time.Time
}

func (WebauthnCredential) TableName() string { return "authx_webauthn_credentials" }

type OAuthIdentity struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"index"`
	Provider  string `gorm:"uniqueIndex:idx_authx_provider_subject"`
	Subject   string `gorm:"uniqueIndex:idx_authx_provider_subject"`
	Email     string
	CreatedAt time.Time
}

func (OAuthIdentity) TableName() string { return "authx_oauth_identities" }

type AuthToken struct {
	ID         uint      `gorm:"primaryKey"`
	Purpose    string    `gorm:"index"`
	UserID     uint      `gorm:"index"`
	Email      string    `gorm:"index"`
	TokenHash  []byte    `gorm:"uniqueIndex"`
	ExpiresAt  time.Time `gorm:"index"`
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

func (AuthToken) TableName() string { return "authx_tokens" }

// EmailOTP is a short numeric one-time code, scoped by (purpose,email) with an attempt counter. Unlike
// AuthToken (a 256-bit secret matched globally by hash), a 6-digit code MUST be user-scoped or a
// guessed value would match any user's concurrent code, so the natural key is (purpose,email).
type EmailOTP struct {
	ID          uint      `gorm:"primaryKey"`
	Purpose     string    `gorm:"uniqueIndex:idx_authx_email_otp,priority:1"`
	Email       string    `gorm:"uniqueIndex:idx_authx_email_otp,priority:2"`
	CodeHash    []byte    `gorm:""`
	Attempts    int       `gorm:""`
	MaxAttempts int       `gorm:""`
	ExpiresAt   time.Time `gorm:"index"`
	CreatedAt   time.Time
}

func (EmailOTP) TableName() string { return "authx_email_otps" }

type LoginAudit struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    uint   `gorm:"index"`
	Email     string `gorm:"index"`
	IP        string `gorm:"index"`
	Method    string
	Event     string
	Success   bool
	Detail    string
	CreatedAt time.Time `gorm:"index"`
}

func (LoginAudit) TableName() string { return "authx_login_audit" }

// --- store ---

// Store implements authx.CredentialStore over GORM.
type Store struct{ db *gorm.DB }

// compile-time proof the GORM store satisfies the interface.
var _ authx.CredentialStore = (*Store)(nil)

// New migrates the authx tables and returns a Store. It also enforces one user per email
// (defense in depth for account-linking safety); New fails closed if the target DB already
// holds duplicate emails.
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(
		&User{}, &PasswordCredential{}, &WebauthnCredential{}, &OAuthIdentity{}, &AuthToken{}, &EmailOTP{}, &LoginAudit{},
	); err != nil {
		return nil, err
	}
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_authx_users_email ON authx_users (email)`).Error; err != nil {
		return nil, err
	}
	s := &Store{db}
	if err := s.migrateDirectory(); err != nil {
		return nil, err
	}
	if err := s.migrateTwoFactor(); err != nil {
		return nil, err
	}
	if err := s.migrateSessions(); err != nil {
		return nil, err
	}
	if err := s.migrateOrgs(); err != nil {
		return nil, err
	}
	return s, nil
}

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func newPrincipalID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func toAuthUser(u *User) *authx.AuthUser {
	au := &authx.AuthUser{ID: u.ID, Sub: u.Sub, Email: u.Email, Name: u.Name, EmailVerified: u.EmailVerified, Disabled: u.Disabled, Banned: u.Banned, BanReason: u.BanReason, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
	if u.BannedUntil != nil {
		au.BannedUntil = *u.BannedUntil
	}
	return au
}

func (s *Store) UserByEmail(email string) (*authx.AuthUser, error) {
	var u User
	if err := s.db.Where("email = ?", normalizeEmail(email)).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoUser
		}
		return nil, err
	}
	return toAuthUser(&u), nil
}

func (s *Store) UserBySub(sub string) (*authx.AuthUser, error) {
	var u User
	if err := s.db.Where("sub = ?", sub).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoUser
		}
		return nil, err
	}
	return toAuthUser(&u), nil
}

func (s *Store) CreateLocalUser(email, name string) (*authx.AuthUser, error) {
	email = normalizeEmail(email)
	// Pre-check one-user-per-email so a duplicate returns the typed ErrEmailConflict (parity with the
	// in-memory store); the unique index stays the fail-closed backstop under races.
	if _, err := s.UserByEmail(email); err == nil {
		return nil, authx.ErrEmailConflict
	} else if !errors.Is(err, authx.ErrNoUser) {
		return nil, err
	}
	u := User{Sub: "local:" + newPrincipalID(), Email: email, Name: name, CreatedAt: time.Now()}
	if err := s.db.Create(&u).Error; err != nil {
		if _, e2 := s.UserByEmail(email); e2 == nil { // a concurrent create won the race
			return nil, authx.ErrEmailConflict
		}
		return nil, err
	}
	return toAuthUser(&u), nil
}

func (s *Store) SetEmailVerified(userID uint, verified bool) error {
	return s.db.Model(&User{}).Where("id = ?", userID).Update("email_verified", verified).Error
}

func (s *Store) EnsureWebauthnHandle(userID uint) ([]byte, error) {
	var u User
	if err := s.db.First(&u, userID).Error; err != nil {
		return nil, err
	}
	if len(u.WebauthnHandle) > 0 {
		return u.WebauthnHandle, nil
	}
	h := make([]byte, 32)
	if _, err := rand.Read(h); err != nil {
		return nil, err
	}
	if err := s.db.Model(&User{}).Where("id = ?", userID).Update("webauthn_handle", h).Error; err != nil {
		return nil, err
	}
	return h, nil
}

func (s *Store) UserByWebauthnHandle(handle []byte) (*authx.AuthUser, error) {
	var u User
	if err := s.db.Where("webauthn_handle = ?", handle).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoUser
		}
		return nil, err
	}
	return toAuthUser(&u), nil
}

func toPasskey(w *WebauthnCredential) authx.Passkey {
	return authx.Passkey{
		ID: w.ID, CredentialID: w.CredentialID, PublicKey: w.PublicKey, AttestationType: w.AttestationType,
		AAGUID: w.AAGUID, SignCount: w.SignCount, Transports: w.Transports,
		BackupEligible: w.BackupEligible, BackupState: w.BackupState, Name: w.Name,
		CreatedAt: w.CreatedAt, LastUsedAt: w.LastUsedAt,
	}
}

func (s *Store) Passkeys(userID uint) ([]authx.Passkey, error) {
	var rows []WebauthnCredential
	if err := s.db.Where("user_id = ?", userID).Order("created_at").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]authx.Passkey, 0, len(rows))
	for i := range rows {
		out = append(out, toPasskey(&rows[i]))
	}
	return out, nil
}

func (s *Store) AddPasskey(userID uint, p authx.Passkey) error {
	now := time.Now()
	return s.db.Create(&WebauthnCredential{
		UserID: userID, CredentialID: p.CredentialID, PublicKey: p.PublicKey, AttestationType: p.AttestationType,
		AAGUID: p.AAGUID, SignCount: p.SignCount, Transports: p.Transports,
		BackupEligible: p.BackupEligible, BackupState: p.BackupState, Name: p.Name,
		CreatedAt: now, LastUsedAt: now,
	}).Error
}

func (s *Store) TouchPasskey(credentialID []byte, signCount uint32) error {
	// One atomic UPDATE: always refresh last-used, but advance the sign count only forward (it's
	// monotonic per WebAuthn) so a stale/replayed assertion can't regress it under concurrency.
	return s.db.Model(&WebauthnCredential{}).Where("credential_id = ?", credentialID).
		Updates(map[string]any{
			"sign_count":   gorm.Expr("CASE WHEN sign_count < ? THEN ? ELSE sign_count END", signCount, signCount),
			"last_used_at": time.Now(),
		}).Error
}

func (s *Store) RemovePasskey(userID, id uint) error {
	return s.db.Where("id = ? AND user_id = ?", id, userID).Delete(&WebauthnCredential{}).Error
}

func (s *Store) PasswordHash(userID uint) (string, string, error) {
	var pc PasswordCredential
	if err := s.db.Where("user_id = ?", userID).First(&pc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", authx.ErrNoCredential
		}
		return "", "", err
	}
	return pc.Hash, pc.Algo, nil
}

func (s *Store) SetPasswordHash(userID uint, hash, algo string) error {
	now := time.Now()
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"hash", "algo", "updated_at"}),
	}).Create(&PasswordCredential{UserID: userID, Hash: hash, Algo: algo, CreatedAt: now, UpdatedAt: now}).Error
}

func (s *Store) UserByOAuth(provider, subject string) (*authx.AuthUser, error) {
	var oa OAuthIdentity
	if err := s.db.Where("provider = ? AND subject = ?", provider, subject).First(&oa).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoUser
		}
		return nil, err
	}
	var u User
	if err := s.db.First(&u, oa.UserID).Error; err != nil {
		return nil, err
	}
	return toAuthUser(&u), nil
}

func (s *Store) LinkOAuth(userID uint, provider, subject, email string) error {
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "provider"}, {Name: "subject"}},
		DoNothing: true,
	}).Create(&OAuthIdentity{UserID: userID, Provider: provider, Subject: subject, Email: normalizeEmail(email), CreatedAt: time.Now()}).Error
}

func (s *Store) CreateToken(purpose string, userID uint, email string, tokenHash []byte, expiresAt time.Time) error {
	return s.db.Create(&AuthToken{
		Purpose: purpose, UserID: userID, Email: normalizeEmail(email),
		TokenHash: tokenHash, ExpiresAt: expiresAt, CreatedAt: time.Now(),
	}).Error
}

// ConsumeToken atomically redeems a single-use token: locks the row, rejects already-consumed
// or expired tokens, and stamps ConsumedAt.
func (s *Store) ConsumeToken(purpose string, tokenHash []byte) (*authx.TokenClaim, error) {
	var claim *authx.TokenClaim
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var t AuthToken
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("purpose = ? AND token_hash = ?", purpose, tokenHash).First(&t).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return authx.ErrTokenInvalid
		}
		if err != nil {
			return err
		}
		if t.ConsumedAt != nil || time.Now().After(t.ExpiresAt) {
			return authx.ErrTokenInvalid
		}
		now := time.Now()
		if err := tx.Model(&AuthToken{}).Where("id = ?", t.ID).Update("consumed_at", now).Error; err != nil {
			return err
		}
		claim = &authx.TokenClaim{UserID: t.UserID, Email: t.Email}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (s *Store) SetEmail(userID uint, newEmail string) error {
	newEmail = normalizeEmail(newEmail)
	// Uphold one-user-per-email (the unique index is the backstop; this gives a clean typed error).
	var other User
	err := s.db.Where("email = ? AND id <> ?", newEmail, userID).First(&other).Error
	if err == nil {
		return authx.ErrEmailConflict
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return s.db.Model(&User{}).Where("id = ?", userID).
		Updates(map[string]any{"email": newEmail, "email_verified": true}).Error
}

// DeleteUser hard-deletes the user + everything keyed to it, deletes its email OTPs, and anonymizes
// its retained audit rows (GDPR erasure of PII while keeping the forensic count). Idempotent.
func (s *Store) DeleteUser(userID uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.First(&u, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if err := cascadeDeletes(tx, userID); err != nil {
			return err
		}
		if u.Email != "" { // OTPs are keyed by email, not user_id
			if err := tx.Where("email = ?", u.Email).Delete(&EmailOTP{}).Error; err != nil {
				return err
			}
		}
		// Tombstone (not delete) live sessions so IsRevoked keeps denying the deleted user on other
		// devices until the cookie expires; null the PII for GDPR erasure but retain the revoked marker.
		if err := tx.Model(&Session{}).Where("user_id = ? AND revoked_at IS NULL", userID).
			Updates(map[string]any{"revoked_at": time.Now(), "user_agent": "", "ip": ""}).Error; err != nil {
			return err
		}
		return tx.Model(&LoginAudit{}).Where("user_id = ?", userID).
			Updates(map[string]any{"email": "", "ip": ""}).Error
	})
}

func (s *Store) RenamePasskey(userID, id uint, name string) error {
	return s.db.Model(&WebauthnCredential{}).Where("id = ? AND user_id = ?", id, userID).
		Update("name", name).Error
}

func (s *Store) UnlinkOAuth(userID uint, provider string) error {
	return s.db.Where("user_id = ? AND provider = ?", userID, provider).Delete(&OAuthIdentity{}).Error
}

func (s *Store) OAuthIdentities(userID uint) ([]string, error) {
	var rows []OAuthIdentity
	if err := s.db.Where("user_id = ?", userID).Order("provider").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].Provider)
	}
	return out, nil
}

func (s *Store) CreateEmailOTP(purpose, email string, codeHash []byte, expiresAt time.Time, maxAttempts int) error {
	email = normalizeEmail(email)
	now := time.Now()
	// Replace any prior OTP for (purpose,email) with an explicit delete-then-insert rather than an
	// upsert, so "one live code per address, attempts reset" holds identically on every backend (a
	// composite-key ON CONFLICT does not resolve uniformly across drivers). The unique index remains
	// as a backstop against a concurrent double-insert.
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("purpose = ? AND email = ?", purpose, email).Delete(&EmailOTP{}).Error; err != nil {
			return err
		}
		return tx.Create(&EmailOTP{
			Purpose: purpose, Email: email, CodeHash: codeHash, MaxAttempts: maxAttempts, ExpiresAt: expiresAt, CreatedAt: now,
		}).Error
	})
}

// VerifyEmailOTP atomically checks a code for (purpose,email): it locks the row, rejects an
// expired/absent code, compares in constant time, and consumes the code on success OR once the attempt
// cap is reached — so a 6-digit code can be guessed at most maxAttempts times.
func (s *Store) VerifyEmailOTP(purpose, email string, codeHash []byte) (*authx.TokenClaim, error) {
	email = normalizeEmail(email)
	var claim *authx.TokenClaim
	// invalid is signaled OUT OF BAND rather than by returning an error from the transaction: a wrong
	// guess still has to COMMIT the attempts increment (returning an error would roll it back and defeat
	// the brute-force cap), so the tx func returns nil on every non-fatal path.
	var invalid bool
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var o EmailOTP
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("purpose = ? AND email = ?", purpose, email).First(&o).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			invalid = true
			return nil
		}
		if err != nil {
			return err
		}
		if time.Now().After(o.ExpiresAt) {
			invalid = true
			return tx.Delete(&EmailOTP{}, o.ID).Error
		}
		if subtle.ConstantTimeCompare(o.CodeHash, codeHash) == 1 {
			claim = &authx.TokenClaim{Email: o.Email}
			return tx.Delete(&EmailOTP{}, o.ID).Error
		}
		invalid = true
		if o.Attempts+1 >= o.MaxAttempts { // this wrong guess exhausts the budget → burn the code
			return tx.Delete(&EmailOTP{}, o.ID).Error
		}
		return tx.Model(&EmailOTP{}).Where("id = ?", o.ID).Update("attempts", o.Attempts+1).Error
	})
	if err != nil {
		return nil, err
	}
	if invalid || claim == nil {
		return nil, authx.ErrTokenInvalid
	}
	return claim, nil
}

// PeekToken validates a token without consuming it (read-only): same not-found/consumed/expired rules
// as ConsumeToken, but leaves the row untouched so the caller can validate downstream input first.
func (s *Store) PeekToken(purpose string, tokenHash []byte) (*authx.TokenClaim, error) {
	var t AuthToken
	err := s.db.Where("purpose = ? AND token_hash = ?", purpose, tokenHash).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, authx.ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if t.ConsumedAt != nil || time.Now().After(t.ExpiresAt) {
		return nil, authx.ErrTokenInvalid
	}
	return &authx.TokenClaim{UserID: t.UserID, Email: t.Email}, nil
}

func (s *Store) RecordAudit(userID uint, email, ip, method, event string, success bool, detail string) {
	_ = s.db.Create(&LoginAudit{
		UserID: userID, Email: normalizeEmail(email), IP: ip, Method: method,
		Event: event, Success: success, Detail: detail, CreatedAt: time.Now(),
	}).Error
}

func (s *Store) RecentFailures(email string, since time.Time) (int, error) {
	var n int64
	err := s.db.Model(&LoginAudit{}).
		Where("email = ? AND success = ? AND created_at >= ?", normalizeEmail(email), false, since).
		Count(&n).Error
	return int(n), err
}

// --- reference Authorizer (the safe verified-email linking rule) ---

// Authorizer returns an authx.Authorizer that upserts the identity on each login with the
// safe account-linking rule. Wrap it if you need provisioning side effects (e.g. create a
// per-user workspace) — call this one first, then do your own work.
func (s *Store) Authorizer() authx.Authorizer { return &authorizer{s} }

type authorizer struct{ s *Store }

func (a *authorizer) Authorize(_ context.Context, id authx.Identity) (string, error) {
	_, err := a.s.UpsertUserOnLogin(id.Subject, id.Email, id.Name, id.EmailVerified)
	return "", err
}

// UpsertUserOnLogin records/updates the identity. CRITICAL SAFETY RULE: when no row matches the
// subject but one exists for the email, it is adopted ONLY if that row is an operator-seeded
// "bootstrap:" placeholder or already EmailVerified. An unverified, non-bootstrap row is an
// unproven squatter (e.g. a password signup that never confirmed the address); adopting it would
// hand its credentials to whoever logs in next — account takeover. It returns ErrEmailConflict
// instead. `emailVerified` asserts the incoming login proved the address (OIDC/social/redeemed).
func (s *Store) UpsertUserOnLogin(sub, email, name string, emailVerified bool) (*authx.AuthUser, error) {
	email = normalizeEmail(email)
	var u User
	err := s.db.Where("sub = ?", sub).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var existing User
		if e2 := s.db.Where("email = ?", email).First(&existing).Error; e2 == nil {
			bootstrap := strings.HasPrefix(existing.Sub, "bootstrap:")
			if bootstrap || existing.EmailVerified {
				// Rebinding an existing (verified) row to a NEW subject is safe only when THIS login
				// proved the email — otherwise an unproven login (e.g. an IdP that permits unverified
				// email claims) could seize a verified account. Bootstrap placeholders are
				// operator-seeded and safe to claim on first login regardless.
				if !bootstrap && !emailVerified {
					return nil, authx.ErrEmailConflict
				}
				existing.Sub, existing.Name, existing.LastLoginAt = sub, name, time.Now()
				if emailVerified {
					existing.EmailVerified = true
				}
				if err := s.db.Save(&existing).Error; err != nil {
					return nil, err
				}
				return toAuthUser(&existing), nil
			}
			// The existing row is an unverified, non-bootstrap squatter. If the INCOMING login
			// proved the email (OIDC/social/redeemed), reclaim the address: the squatter never
			// owned it, so we delete it (and its credentials) and provision a clean verified user.
			// If the incoming did NOT prove the email, refuse rather than risk a takeover.
			if !emailVerified {
				return nil, authx.ErrEmailConflict
			}
			// Reclaim atomically: delete the squatter AND create the clean user in one transaction,
			// so a crash between the two can't leave the email owned by nobody (and thus unusable).
			u = User{Sub: sub, Email: email, Name: name, EmailVerified: emailVerified, CreatedAt: time.Now(), LastLoginAt: time.Now()}
			if err := s.db.Transaction(func(tx *gorm.DB) error {
				if derr := cascadeDeletes(tx, existing.ID); derr != nil {
					return derr
				}
				return tx.Create(&u).Error
			}); err != nil {
				return nil, err
			}
			return toAuthUser(&u), nil
		}
		u = User{Sub: sub, Email: email, Name: name, EmailVerified: emailVerified, CreatedAt: time.Now(), LastLoginAt: time.Now()}
		if err := s.db.Create(&u).Error; err != nil {
			return nil, err
		}
		return toAuthUser(&u), nil
	}
	if err != nil {
		return nil, err
	}
	// Moving this row onto an email another row already owns must return the typed ErrEmailConflict
	// (parity with the in-memory store), not a raw driver unique-constraint error — the unique index is
	// only the fail-closed backstop.
	if email != normalizeEmail(u.Email) {
		var other User
		if e2 := s.db.Where("email = ? AND id <> ?", email, u.ID).First(&other).Error; e2 == nil {
			return nil, authx.ErrEmailConflict
		} else if !errors.Is(e2, gorm.ErrRecordNotFound) {
			return nil, e2
		}
	}
	u.Email, u.Name, u.LastLoginAt = email, name, time.Now()
	if emailVerified {
		u.EmailVerified = true
	}
	if err := s.db.Save(&u).Error; err != nil {
		return nil, err
	}
	return toAuthUser(&u), nil
}

// deleteUserCascade removes a user and everything keyed to it (credentials, tokens, OAuth links,
// group memberships) in one transaction. Used to reclaim an email from an unverified squatter.
// LoginAudit rows are deliberately NOT deleted — the forensic trail is kept, and orphaned audit
// rows grant no access (they can't resolve to a login).
func (s *Store) deleteUserCascade(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error { return cascadeDeletes(tx, id) })
}

// cascadeDeletes removes a user + everything keyed to it on the given tx handle (no transaction of
// its own, so a caller can compose it with a create for an atomic reclaim).
func cascadeDeletes(tx *gorm.DB, id uint) error {
	// NOTE: Session rows are intentionally NOT deleted here. Deleting them would make IsRevoked (an
	// absent SID reads as "not revoked") silently re-admit a hard-deleted user on their other devices.
	// DeleteUser tombstones the sessions as revoked instead; reclaim targets (unverified squatters) have
	// no sessions, so their omission here is harmless.
	for _, m := range []any{&PasswordCredential{}, &WebauthnCredential{}, &OAuthIdentity{}, &AuthToken{}, &GroupMembership{}, &OrgMembership{}, &TOTPCredential{}, &RecoveryCode{}} {
		if err := tx.Where("user_id = ?", id).Delete(m).Error; err != nil {
			return err
		}
	}
	return tx.Delete(&User{}, id).Error
}
