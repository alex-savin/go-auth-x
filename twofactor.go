package authx

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	twoFactorPendingCookie = "sweep_2fa_pending"
	twoFactorPendingTTL    = 5 * time.Minute
	recoveryCodeCount      = 10
)

// TOTPInfo is a user's stored TOTP state. Secret is the base32 shared secret; Enabled is false while
// enrollment is pending (secret set but not yet confirmed with a valid code); LastStep is the most
// recently consumed time-step, used to reject a replayed code.
type TOTPInfo struct {
	Secret   string
	Enabled  bool
	LastStep uint64
}

// TwoFactorStore is OPTIONAL persistence for TOTP + recovery codes. Wire it with SetTwoFactorStore to
// enable two-factor auth. It's separate from CredentialStore so consumers that don't want 2FA are
// unaffected. User ids match CredentialStore. Recovery codes are stored as sha256 hashes; consuming
// one removes it. Secrets should be encrypted at rest by the implementation.
type TwoFactorStore interface {
	TOTP(userID uint) (*TOTPInfo, error)            // ErrNoCredential if the user has no TOTP
	SetTOTPSecret(userID uint, secret string) error // (re)enroll: store secret, Enabled=false, LastStep=0
	EnableTOTP(userID uint) error                   // confirm enrollment
	DisableTOTP(userID uint) error                  // remove TOTP + all recovery codes
	SetTOTPLastStep(userID uint, step uint64) error // replay guard, set after a successful verify

	ReplaceRecoveryCodes(userID uint, hashes [][]byte) error    // set at enrollment (replaces any existing)
	ConsumeRecoveryCode(userID uint, hash []byte) (bool, error) // true if it existed and was removed
	RecoveryCodesRemaining(userID uint) (int, error)
}

// SetTwoFactorStore enables optional TOTP two-factor auth + recovery codes.
func (a *Authenticator) SetTwoFactorStore(s TwoFactorStore) { a.twoFactor = s }

// TwoFactorEnabled reports whether 2FA is wired at all (a store is set).
func (a *Authenticator) TwoFactorEnabled() bool { return a != nil && a.twoFactor != nil }

// userHasTOTP reports whether the user has CONFIRMED TOTP (so login must challenge for a code).
func (a *Authenticator) userHasTOTP(userID uint) bool {
	if a.twoFactor == nil {
		return false
	}
	info, err := a.twoFactor.TOTP(userID)
	return err == nil && info != nil && info.Enabled
}

// --- recovery codes ---

// newRecoveryCodes returns n single-use codes (plaintext, shown to the user ONCE) plus their sha256
// hashes for storage.
func newRecoveryCodes(n int) (codes []string, hashes [][]byte, err error) {
	for i := 0; i < n; i++ {
		buf := make([]byte, 5) // 10 hex chars
		if _, err = rand.Read(buf); err != nil {
			return nil, nil, err
		}
		code := hex.EncodeToString(buf)
		codes = append(codes, code)
		hashes = append(hashes, recoveryHash(code))
	}
	return codes, hashes, nil
}

// recoveryHash normalizes a code (trim, lower-case, strip spaces/dashes) then sha256s it, so a code
// entered with incidental formatting still matches.
func recoveryHash(code string) []byte {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.NewReplacer(" ", "", "-", "").Replace(code)
	h := sha256.Sum256([]byte(code))
	return h[:]
}

// --- the 2fa-pending cookie: a short-lived signed token that carries the half-authenticated
// identity between the first factor and POST /auth/2fa/verify (so the second step needs no re-auth).

type pendingClaims struct {
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Role     string   `json:"role,omitempty"`
	Remember bool     `json:"rm,omitempty"`
	jwt.RegisteredClaims
}

func (a *Authenticator) mintPending(id Identity, role string, remember bool) (string, error) {
	now := time.Now()
	return signJWT(a.cfg.SessionSecret, pendingClaims{
		Email: id.Email, Name: id.Name, Groups: id.Groups, Role: role, Remember: remember,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   id.Subject,
			Audience:  jwt.ClaimStrings{audPending},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(twoFactorPendingTTL)),
		},
	})
}

// completePendingLogin mints the real session from a validated 2fa-pending identity and clears the
// pending cookie — the shared final step for both the TOTP/recovery and passkey second factors.
func (a *Authenticator) completePendingLogin(c *reqCtx, pc *pendingClaims) error {
	a.clearCookie(c, twoFactorPendingCookie)
	ttl := sessionTTL
	if pc.Remember {
		ttl = rememberTTL
	}
	session, err := mintSession(a.cfg.SessionSecret, pc.Subject, pc.Email, pc.Name, pc.Role, "", pc.Groups, time.Now(), ttl)
	if err != nil {
		return err
	}
	a.setCookie(c, sessionCookie, session, int(ttl/time.Second))
	a.issueCSRF(c)
	return nil
}

func (a *Authenticator) parsePending(token string) (*pendingClaims, error) {
	if token == "" {
		return nil, errors.New("no 2fa-pending cookie")
	}
	var c pendingClaims
	if err := parseJWT(a.cfg.SessionSecret, token, &c, audPending); err != nil {
		return nil, err
	}
	if c.Subject == "" {
		return nil, errors.New("2fa-pending missing subject")
	}
	return &c, nil
}
