package gormstore

import (
	"encoding/hex"

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

func (s *Store) TOTP(userID uint) (*authx.TOTPInfo, error) {
	var t TOTPCredential
	if err := s.db.First(&t, "user_id = ?", userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, authx.ErrNoCredential
		}
		return nil, err
	}
	return &authx.TOTPInfo{Secret: t.Secret, Enabled: t.Enabled, LastStep: t.LastStep}, nil
}

func (s *Store) SetTOTPSecret(userID uint, secret string) error {
	// Upsert; a (re)enroll resets enabled + lastStep.
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.Assignments(map[string]any{"secret": secret, "enabled": false, "last_step": 0}),
	}).Create(&TOTPCredential{UserID: userID, Secret: secret}).Error
}

func (s *Store) EnableTOTP(userID uint) error {
	return s.db.Model(&TOTPCredential{}).Where("user_id = ?", userID).Update("enabled", true).Error
}

func (s *Store) DisableTOTP(userID uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&TOTPCredential{}, "user_id = ?", userID).Error; err != nil {
			return err
		}
		return tx.Delete(&RecoveryCode{}, "user_id = ?", userID).Error
	})
}

func (s *Store) SetTOTPLastStep(userID uint, step uint64) error {
	return s.db.Model(&TOTPCredential{}).Where("user_id = ?", userID).Update("last_step", step).Error
}

func (s *Store) ReplaceRecoveryCodes(userID uint, hashes [][]byte) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&RecoveryCode{}, "user_id = ?", userID).Error; err != nil {
			return err
		}
		rows := make([]RecoveryCode, 0, len(hashes))
		for _, h := range hashes {
			rows = append(rows, RecoveryCode{UserID: userID, Hash: hex.EncodeToString(h)})
		}
		if len(rows) == 0 {
			return nil
		}
		return tx.Create(&rows).Error
	})
}

func (s *Store) ConsumeRecoveryCode(userID uint, hash []byte) (bool, error) {
	res := s.db.Where("user_id = ? AND hash = ?", userID, hex.EncodeToString(hash)).Delete(&RecoveryCode{})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (s *Store) RecoveryCodesRemaining(userID uint) (int, error) {
	var n int64
	err := s.db.Model(&RecoveryCode{}).Where("user_id = ?", userID).Count(&n).Error
	return int(n), err
}
