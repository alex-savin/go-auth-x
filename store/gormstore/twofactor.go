package gormstore

import (
	"encoding/hex"
	"errors"

	authx "github.com/alex-savin/go-auth-x"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var _ authx.TwoFactorStore = (*Store)(nil)

// TOTPCredential holds a user's TOTP secret + state (one row per user). The secret is stored as the
// base32 string; wrap the DB or column with encryption-at-rest if your threat model requires it.
type TOTPCredential struct {
	UserID   uint `gorm:"primaryKey"` // one row per user
	Secret   string
	Enabled  bool
	LastStep uint64
}

func (TOTPCredential) TableName() string { return "authx_totp_credentials" }

// RecoveryCode is a single-use 2FA recovery code, stored as hex(sha256(code)). Consuming one deletes
// the row (atomic single-use).
type RecoveryCode struct {
	ID     uint   `gorm:"primaryKey"`
	UserID uint   `gorm:"index:idx_authx_recovery,priority:1"`
	Hash   string `gorm:"index:idx_authx_recovery,priority:2"`
}

func (RecoveryCode) TableName() string { return "authx_recovery_codes" }

func (s *Store) migrateTwoFactor() error {
	return s.db.AutoMigrate(&TOTPCredential{}, &RecoveryCode{})
}

func (s *Store) TOTP(userID string) (*authx.TOTPInfo, error) {
	n, ok := parseID(userID)
	if !ok {
		return nil, authx.ErrNoCredential
	}
	var t TOTPCredential
	if err := s.db.First(&t, "user_id = ?", n).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoCredential
		}
		return nil, err
	}
	return &authx.TOTPInfo{Secret: t.Secret, Enabled: t.Enabled, LastStep: t.LastStep}, nil
}

func (s *Store) SetTOTPSecret(userID, secret string) error {
	n, ok := parseID(userID)
	if !ok {
		return authx.ErrNoUser
	}
	// Upsert; a (re)enroll resets enabled + lastStep.
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.Assignments(map[string]any{"secret": secret, "enabled": false, "last_step": 0}),
	}).Create(&TOTPCredential{UserID: n, Secret: secret}).Error
}

func (s *Store) EnableTOTP(userID string) error {
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	return s.db.Model(&TOTPCredential{}).Where("user_id = ?", n).Update("enabled", true).Error
}

func (s *Store) DisableTOTP(userID string) error {
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&TOTPCredential{}, "user_id = ?", n).Error; err != nil {
			return err
		}
		return tx.Delete(&RecoveryCode{}, "user_id = ?", n).Error
	})
}

func (s *Store) SetTOTPLastStep(userID string, step uint64) error {
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	return s.db.Model(&TOTPCredential{}).Where("user_id = ?", n).Update("last_step", step).Error
}

// ClaimTOTPStep atomically advances last_step to step only if it is newer, via a single conditional
// UPDATE (WHERE last_step < step). RowsAffected==1 means this request won the step — the DB serializes
// concurrent claims, so a replayed code can't be accepted twice.
func (s *Store) ClaimTOTPStep(userID string, step uint64) (bool, error) {
	n, ok := parseID(userID)
	if !ok {
		return false, nil
	}
	res := s.db.Model(&TOTPCredential{}).
		Where("user_id = ? AND last_step < ?", n, step).
		Update("last_step", step)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

func (s *Store) ReplaceRecoveryCodes(userID string, hashes [][]byte) error {
	n, ok := parseID(userID)
	if !ok {
		return authx.ErrNoUser
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&RecoveryCode{}, "user_id = ?", n).Error; err != nil {
			return err
		}
		rows := make([]RecoveryCode, 0, len(hashes))
		for _, h := range hashes {
			rows = append(rows, RecoveryCode{UserID: n, Hash: hex.EncodeToString(h)})
		}
		if len(rows) == 0 {
			return nil
		}
		return tx.Create(&rows).Error
	})
}

func (s *Store) ConsumeRecoveryCode(userID string, hash []byte) (bool, error) {
	n, ok := parseID(userID)
	if !ok {
		return false, nil
	}
	res := s.db.Where("user_id = ? AND hash = ?", n, hex.EncodeToString(hash)).Delete(&RecoveryCode{})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (s *Store) RecoveryCodesRemaining(userID string) (int, error) {
	pk, ok := parseID(userID)
	if !ok {
		return 0, nil
	}
	var n int64
	err := s.db.Model(&RecoveryCode{}).Where("user_id = ?", pk).Count(&n).Error
	return int(n), err
}
