package authx

import (
	"errors"
	"log"
	"time"
)

// Sentinels returned by a CredentialStore so the auth package can branch without knowing
// the storage layer (GORM lives in the tenant package).
var (
	ErrNoUser       = errors.New("authx: no such user")
	ErrNoCredential = errors.New("authx: no credential")
	ErrTokenInvalid = errors.New("authx: token invalid or expired")
	// ErrEmailConflict is returned by a reference Authorizer's identity upsert when a login's
	// email already belongs to a different, unproven (unverified, non-bootstrap) account row.
	// Refusing rather than merging is what prevents account takeover; surface it as a 409.
	ErrEmailConflict = errors.New("authx: an account already exists for this email")
)

// AuthUser is the auth package's storage-agnostic view of a control-plane user.
type AuthUser struct {
	ID            uint
	Sub           string
	Email         string
	Name          string
	EmailVerified bool
	Disabled      bool
	// Ban is a time-boxed login block with a reason, distinct from Disabled (an operator off-switch).
	// Banned + zero BannedUntil = permanent; Banned + a future BannedUntil = until that instant.
	Banned      bool
	BannedUntil time.Time
	BanReason   string
	// Timestamps for SCIM meta.created / meta.lastModified. Best-effort — a store that doesn't
	// track them leaves them zero and SCIM omits the field.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// loginBlocked reports whether this user may not complete a login, and a user-facing reason. It folds
// the Disabled off-switch and an active (unexpired) Ban into the single gate the login callers use.
func (u *AuthUser) loginBlocked() (bool, string) {
	if u == nil {
		return false, ""
	}
	if u.Disabled {
		return true, "this account has been disabled"
	}
	if u.Banned && (u.BannedUntil.IsZero() || time.Now().Before(u.BannedUntil)) {
		if u.BanReason != "" {
			return true, "this account is suspended: " + u.BanReason
		}
		return true, "this account is suspended"
	}
	return false, ""
}

// TokenClaim is what a redeemed single-use token resolves to.
type TokenClaim struct {
	UserID uint
	Email  string
}

// Passkey is the auth package's storage-agnostic view of a registered WebAuthn credential.
type Passkey struct {
	ID              uint
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	Transports      string // CSV of authenticator transports
	BackupEligible  bool
	BackupState     bool
	Name            string
	CreatedAt       time.Time
	LastUsedAt      time.Time
}

// CredentialStore is the persistence the in-app auth methods need. It is implemented by
// the control plane (tenant package), so the auth package stays storage-agnostic — the
// same boundary the Authorizer hook uses. Lookups return ErrNoUser / ErrNoCredential when
// absent. The passkey and social-identity methods are added in later phases.
type CredentialStore interface {
	// Identity
	UserByEmail(email string) (*AuthUser, error)
	UserBySub(sub string) (*AuthUser, error)
	CreateLocalUser(email, name string) (*AuthUser, error) // Sub="local:<uuid>", EmailVerified=false
	SetEmailVerified(userID uint, verified bool) error
	// SetEmail changes a user's email (used by the verified change-email flow AFTER the new address is
	// proven). It must uphold the one-user-per-email invariant, returning ErrEmailConflict if another
	// user already owns newEmail.
	SetEmail(userID uint, newEmail string) error
	// DeleteUser hard-deletes a user and everything keyed to it (credentials, passkeys, tokens, OAuth
	// links, 2FA, group memberships). Audit rows are retained but any PII (email/IP) is anonymized, so
	// the forensic count survives an erasure. Idempotent: deleting an absent user is not an error.
	DeleteUser(userID uint) error

	// Passkeys (WebAuthn)
	EnsureWebauthnHandle(userID uint) ([]byte, error)      // get-or-create the stable user handle
	UserByWebauthnHandle(handle []byte) (*AuthUser, error) // resolve a discoverable login
	Passkeys(userID uint) ([]Passkey, error)
	AddPasskey(userID uint, p Passkey) error
	TouchPasskey(credentialID []byte, signCount uint32) error // update sign count + last-used
	RemovePasskey(userID, id uint) error
	RenamePasskey(userID, id uint, name string) error // relabel a passkey; no-op if not the user's

	// Password
	PasswordHash(userID uint) (hash, algo string, err error) // ErrNoCredential if unset
	SetPasswordHash(userID uint, hash, algo string) error

	// Social (OAuth) identities — natural key (provider, subject), NOT email, so an upstream
	// email change doesn't fork the account.
	UserByOAuth(provider, subject string) (*AuthUser, error)      // ErrNoUser if unlinked
	LinkOAuth(userID uint, provider, subject, email string) error // idempotent per (provider,subject)
	UnlinkOAuth(userID uint, provider string) error               // remove the user's link to a provider
	OAuthIdentities(userID uint) ([]string, error)                // provider slugs the user has linked

	// Single-use, hashed-at-rest email tokens (magic-link, verify-email, password-reset, invite)
	CreateToken(purpose string, userID uint, email string, tokenHash []byte, expiresAt time.Time) error
	ConsumeToken(purpose string, tokenHash []byte) (*TokenClaim, error) // marks consumed atomically; ErrTokenInvalid
	// PeekToken validates a token (exists, unconsumed, unexpired) and returns its claim WITHOUT consuming
	// it, so a caller can validate downstream input (e.g. the new password) before burning a single-use
	// link. ErrTokenInvalid on a miss/expiry.
	PeekToken(purpose string, tokenHash []byte) (*TokenClaim, error)

	// Email OTP (short numeric codes). Unlike the 256-bit tokens above these are brute-forceable, so
	// they are scoped by (purpose,email) — NOT matched globally by hash — and carry an attempt counter.
	// CreateEmailOTP replaces any existing OTP for (purpose,email). VerifyEmailOTP atomically compares
	// (constant-time), increments the attempt count, and invalidates the code on success OR once
	// maxAttempts is exceeded; it returns ErrTokenInvalid on any miss/expiry/exhaustion.
	CreateEmailOTP(purpose, email string, codeHash []byte, expiresAt time.Time, maxAttempts int) error
	VerifyEmailOTP(purpose, email string, codeHash []byte) (*TokenClaim, error)

	// Audit + lockout
	RecordAudit(userID uint, email, ip, method, event string, success bool, detail string)
	RecentFailures(email string, since time.Time) (int, error)
}

// Mailer sends the in-app auth emails. Implemented by internal/email; the auth package
// owns the message templates and calls Send. nil/!Configured() disables email methods.
type Mailer interface {
	Send(to, subject, htmlBody, textBody string) error
	Configured() bool
}

// SetCredentialStore installs the in-app credential persistence (enables local methods).
func (a *Authenticator) SetCredentialStore(cs CredentialStore) { a.creds = cs }

// SetMailer installs the email sender for magic-link/verify/reset mails.
func (a *Authenticator) SetMailer(m Mailer) { a.email = m }

// SetLocalEnabled toggles whether the in-app auth methods (password / passkey / email magic-link + OTP)
// are wired (mirrors the AUTH_LOCAL env flag). OIDC and social login are independent of this flag —
// each social provider activates on its own credentials, and OIDC on its issuer.
func (a *Authenticator) SetLocalEnabled(on bool) {
	a.localEnabled = on
	if on {
		if len(a.cfg.SessionSecret) < minSessionSecret {
			// Local auth mints signed cookies; a weak/absent key makes them forgeable. New() can't
			// catch this (local is enabled after construction), so warn loudly here — signJWT also
			// fails closed so no cookie is ever signed with a short key.
			log.Printf("authx: WARNING SESSION_SECRET is shorter than %d bytes; local auth cannot mint sessions until it is set", minSessionSecret)
		}
		a.enableLimiters()
		a.enableWebauthn()
	}
}

// LocalEnabled reports whether in-app auth methods are active (flag on + a credential store).
func (a *Authenticator) LocalEnabled() bool { return a != nil && a.localEnabled && a.creds != nil }
