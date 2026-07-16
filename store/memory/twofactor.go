package memory

import (
	"encoding/hex"

	authx "github.com/alex-savin/go-auth-x"
)

var _ authx.TwoFactorStore = (*Store)(nil)

func (s *Store) TOTP(userID string) (*authx.TOTPInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil, authx.ErrNoCredential
	}
	r := s.totp[n]
	if r == nil {
		return nil, authx.ErrNoCredential
	}
	return &authx.TOTPInfo{Secret: r.secret, Enabled: r.enabled, LastStep: r.lastStep}, nil
}

func (s *Store) SetTOTPSecret(userID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	s.totp[n] = &totpRec{secret: secret}
	return nil
}

func (s *Store) EnableTOTP(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	if r := s.totp[n]; r != nil {
		r.enabled = true
	}
	return nil
}

func (s *Store) DisableTOTP(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	delete(s.totp, n)
	delete(s.recovery, n)
	return nil
}

func (s *Store) SetTOTPLastStep(userID string, step uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	if r := s.totp[n]; r != nil {
		r.lastStep = step
	}
	return nil
}

// ClaimTOTPStep atomically advances lastStep to step iff step is newer, under the store lock, so the
// replay check and the write are one operation (no TOCTOU).
func (s *Store) ClaimTOTPStep(userID string, step uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return false, authx.ErrNoCredential
	}
	r := s.totp[n]
	if r == nil {
		return false, authx.ErrNoCredential
	}
	if step <= r.lastStep {
		return false, nil
	}
	r.lastStep = step
	return true, nil
}

func (s *Store) ReplaceRecoveryCodes(userID string, hashes [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return nil
	}
	set := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		set[hex.EncodeToString(h)] = true
	}
	s.recovery[n] = set
	return nil
}

func (s *Store) ConsumeRecoveryCode(userID string, hash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return false, nil
	}
	key := hex.EncodeToString(hash)
	if set := s.recovery[n]; set != nil && set[key] {
		delete(set, key)
		return true, nil
	}
	return false, nil
}

func (s *Store) RecoveryCodesRemaining(userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := parseID(userID)
	if !ok {
		return 0, nil
	}
	return len(s.recovery[n]), nil
}
