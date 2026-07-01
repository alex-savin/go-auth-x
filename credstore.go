package authx

import (
	"errors"
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
	// Timestamps for SCIM meta.created / meta.lastModified. Best-effort — a store that doesn't
	// track them leaves them zero and SCIM omits the field.
	CreatedAt time.Time
	UpdatedAt time.Time
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

	// Passkeys (WebAuthn)
	EnsureWebauthnHandle(userID uint) ([]byte, error)      // get-or-create the stable user handle
	UserByWebauthnHandle(handle []byte) (*AuthUser, error) // resolve a discoverable login
	Passkeys(userID uint) ([]Passkey, error)
	AddPasskey(userID uint, p Passkey) error
	TouchPasskey(credentialID []byte, signCount uint32) error // update sign count + last-used
	RemovePasskey(userID, id uint) error

	// Password
	PasswordHash(userID uint) (hash, algo string, err error) // ErrNoCredential if unset
	SetPasswordHash(userID uint, hash, algo string) error

	// Social (OAuth) identities — natural key (provider, subject), NOT email, so an upstream
	// email change doesn't fork the account.
	UserByOAuth(provider, subject string) (*AuthUser, error)      // ErrNoUser if unlinked
	LinkOAuth(userID uint, provider, subject, email string) error // idempotent per (provider,subject)

	// Single-use, hashed-at-rest email tokens (magic-link, verify-email, password-reset, invite)
	CreateToken(purpose string, userID uint, email string, tokenHash []byte, expiresAt time.Time) error
	ConsumeToken(purpose string, tokenHash []byte) (*TokenClaim, error) // marks consumed atomically; ErrTokenInvalid

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

// SetLocalEnabled toggles whether in-app auth methods (password/passkey/email/social) are
// wired (mirrors the AUTH_LOCAL env flag). OIDC is unaffected.
func (a *Authenticator) SetLocalEnabled(on bool) {
	a.localEnabled = on
	if on {
		a.enableLimiters()
		a.enableWebauthn()
	}
}

// LocalEnabled reports whether in-app auth methods are active (flag on + a credential store).
func (a *Authenticator) LocalEnabled() bool { return a != nil && a.localEnabled && a.creds != nil }
