package authx

import (
	"crypto/sha256"
	"time"
)

// AuthToken purposes (the string stored in auth_tokens.purpose).
const (
	purposeMagicLogin    = "magic_login"
	purposeVerifyEmail   = "verify_email"
	purposePasswordReset = "password_reset"
	purposeInvite        = "invite"
	purposeChangeEmail   = "change_email" // verify a NEW address before rebinding it
	purposeEmailOTP      = "email_otp"    // short numeric sign-in code (see emailotp.go)
	// purposeOrgInvite is a PREFIX: the stored purpose is "org_invite:<orgID>:<role>", binding the
	// invite to one org + role. The accept URL carries org/role in the query, so a tampered value
	// reconstructs a purpose that matches no stored token (see orgInvitePurpose).
	purposeOrgInvite = "org_invite"
)

// Token TTLs by purpose (used by the Phase 1+ email flows).
const (
	ttlMagicLogin    = 15 * time.Minute
	ttlVerifyEmail   = 24 * time.Hour
	ttlPasswordReset = 1 * time.Hour
	ttlInvite        = 7 * 24 * time.Hour
	ttlChangeEmail   = 1 * time.Hour
)

// newToken returns a fresh random URL-safe token plus its sha256 hash. The raw token is
// emailed to the user; only the hash is persisted, so a DB leak yields no usable links.
func newToken() (raw string, hash []byte) {
	raw = randToken() // 32 bytes crypto/rand, base64url (defined in handlers.go)
	return raw, hashToken(raw)
}

// hashToken returns sha256(raw) — the value stored at rest and matched on redemption.
func hashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}
