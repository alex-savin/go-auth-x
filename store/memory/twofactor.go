package memory

import (
	"encoding/hex"

	authx "github.com/alex-savin/go-auth-x"
)

var _ authx.TwoFactorStore = (*Store)(nil)

func (s *Store) TOTP(userID uint) (*authx.TOTPInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.totp[userID]
	if r == nil {
		return nil, authx.ErrNoCredential
	}
	return &authx.TOTPInfo{Secret: r.secret, Enabled: r.enabled, LastStep: r.lastStep}, nil
}

func (s *Store) SetTOTPSecret(userID uint, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totp[userID] = &totpRec{secret: secret}
	return nil
}

func (s *Store) EnableTOTP(userID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.totp[userID]; r != nil {
		r.enabled = true
	}
	return nil
}

func (s *Store) DisableTOTP(userID uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.totp, userID)
	delete(s.recovery, userID)
	return nil
}

func (s *Store) SetTOTPLastStep(userID uint, step uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.totp[userID]; r != nil {
		r.lastStep = step
	}
	return nil
}

func (s *Store) ReplaceRecoveryCodes(userID uint, hashes [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		set[hex.EncodeToString(h)] = true
	}
	s.recovery[userID] = set
	return nil
}

func (s *Store) ConsumeRecoveryCode(userID uint, hash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(hash)
	if set := s.recovery[userID]; set != nil && set[key] {
		delete(set, key)
		return true, nil
	}
	return false, nil
}

func (s *Store) RecoveryCodesRemaining(userID uint) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recovery[userID]), nil
}
