// Package gormstore is a reference GORM-backed implementation of authx.CredentialStore plus a
// safe reference Authorizer (identity upsert with verified-email account-linking). It is
// self-contained: all tables are prefixed authx_ and migrated by New, so it drops into any
// Postgres/SQLite GORM app without colliding with existing tables.
package gormstore

import (
	"context"
	"crypto/rand"
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
	ID             uint      `gorm:"primaryKey"`
	Sub            string    `gorm:"uniqueIndex"`
	Email          string    `gorm:"index"`
	Name           string    `gorm:""`
	EmailVerified  bool      `gorm:""`
	WebauthnHandle []byte    `gorm:""`
	Disabled       bool      `gorm:""`
	CreatedAt      time.Time `gorm:""`
	LastLoginAt    time.Time `gorm:""`
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
	ID         uint   `gorm:"primaryKey"`
	Purpose    string `gorm:"index"`
	UserID     uint   `gorm:"index"`
	Email      string `gorm:"index"`
	TokenHash  []byte `gorm:"uniqueIndex"`
	ExpiresAt  time.Time `gorm:"index"`
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

func (AuthToken) TableName() string { return "authx_tokens" }

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
		&User{}, &PasswordCredential{}, &WebauthnCredential{}, &OAuthIdentity{}, &AuthToken{}, &LoginAudit{},
	); err != nil {
		return nil, err
	}
	if err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uniq_authx_users_email ON authx_users (email)`).Error; err != nil {
		return nil, err
	}
	return &Store{db}, nil
}

func normalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func newPrincipalID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func toAuthUser(u *User) *authx.AuthUser {
	return &authx.AuthUser{ID: u.ID, Sub: u.Sub, Email: u.Email, Name: u.Name, EmailVerified: u.EmailVerified, Disabled: u.Disabled}
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
	u := User{Sub: "local:" + newPrincipalID(), Email: normalizeEmail(email), Name: name, CreatedAt: time.Now()}
	if err := s.db.Create(&u).Error; err != nil {
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
	return s.db.Model(&WebauthnCredential{}).Where("credential_id = ?", credentialID).
		Updates(map[string]any{"sign_count": signCount, "last_used_at": time.Now()}).Error
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
	_, err := a.s.UpsertUserOnLogin(id.Subject, id.Email, id.Name, true)
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
			if strings.HasPrefix(existing.Sub, "bootstrap:") || existing.EmailVerified {
				existing.Sub, existing.Name, existing.LastLoginAt = sub, name, time.Now()
				if emailVerified {
					existing.EmailVerified = true
				}
				if err := s.db.Save(&existing).Error; err != nil {
					return nil, err
				}
				return toAuthUser(&existing), nil
			}
			return nil, authx.ErrEmailConflict
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
	u.Email, u.Name, u.LastLoginAt = email, name, time.Now()
	if emailVerified {
		u.EmailVerified = true
	}
	if err := s.db.Save(&u).Error; err != nil {
		return nil, err
	}
	return toAuthUser(&u), nil
}
