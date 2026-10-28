package authx

import (
	"errors"
	"time"
)

// --- OAuth provider storage (used by the oidcprovider subpackage) ---
//
// The records an embedded OAuth 2.1 / OIDC provider keeps: the clients (registered by the app or
// dynamically by the client itself), the authorization requests in flight, the grants a user made
// (one per approval, the family every token of it belongs to), the access and refresh tokens, and
// the signing keys. The interface lives here — like SessionStore and DirectoryStore — so the
// reference stores implement it without importing the provider's dependencies. Secrets are never
// stored: client secrets, codes and refresh tokens are kept as SHA-256 hashes (hex), and an access
// token's ID is useless without the provider's encryption key.

var (
	// ErrOAuthNotFound is returned for an absent client, request, grant, token or key.
	ErrOAuthNotFound = errors.New("authx: oauth record not found")
	// ErrOAuthTokenUsed is returned by UseOAuthRefreshToken when the token was already exchanged.
	ErrOAuthTokenUsed = errors.New("authx: refresh token already used")
)

// OAuthClient is a client application. A dynamically registered client (Dynamic) was created by
// the client itself through the registration endpoint; an app-registered one by the app.
type OAuthClient struct {
	ID           string
	SecretHash   string // SHA-256 hex of the secret; empty for a public client (AuthMethod "none")
	Name         string
	URI          string // the client's home page, shown on the consent screen
	LogoURI      string
	RedirectURIs []string
	GrantTypes   []string // "authorization_code", "refresh_token"
	AuthMethod   string   // "none", "client_secret_basic" or "client_secret_post"
	Dynamic      bool
	CreatedAt    time.Time
	LastUsedAt   time.Time // last token issued; unused dynamic clients are removed after a while
}

// OAuthAuthRequest is an authorization request between /authorize and the code exchange.
type OAuthAuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              []string
	ResponseType        string
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	Resources           []string // RFC 8707 resource indicators the tokens are bound to
	Prompt              []string
	Subject             string    // the user who signed in for it ("" until then)
	Ref                 string    // the app's reference for the approval (e.g. its own connection id)
	GrantExpiresAt      time.Time // the end the approval sets for the grant (zero = none)
	AuthTime            time.Time // when the user approved
	Done                bool      // approved: the code may be issued
	CodeHash            string    // SHA-256 hex of the issued code
	CodeAt              time.Time
	CreatedAt           time.Time
}

// OAuthGrant is one approval: a user let a client act with these scopes on these resources.
// Every access and refresh token belongs to a grant; revoking it ends them all.
type OAuthGrant struct {
	ID        string
	ClientID  string
	Subject   string
	Scopes    []string
	Resources []string
	Ref       string
	AuthTime  time.Time
	CreatedAt time.Time
	ExpiresAt time.Time  // the grant's end, whatever refreshing does; zero = none
	RevokedAt *time.Time // nil = live
}

// OAuthAccessToken is an issued access token, by its ID (the bearer value is the ID encrypted).
type OAuthAccessToken struct {
	ID        string
	GrantID   string
	ClientID  string
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// OAuthRefreshToken is an issued refresh token, by its hash. It is used once: exchanging it marks
// it used and issues a new one; presenting a used one again means it leaked, and the grant ends.
type OAuthRefreshToken struct {
	Hash      string
	GrantID   string
	ClientID  string
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
}

// OAuthSigningKey is a key the provider signs ID tokens with. PrivatePEM is a PKCS#8 PEM block.
type OAuthSigningKey struct {
	ID         string
	Algorithm  string // "RS256"
	PrivatePEM []byte
	CreatedAt  time.Time
	RetiredAt  *time.Time // still published (to verify older tokens) but no longer signing
}

// OAuthStore persists the provider's records. Reads of an absent record return ErrOAuthNotFound.
// It must be shared by every replica (like a SessionStore); the in-memory store suits one process.
type OAuthStore interface {
	CreateOAuthClient(c *OAuthClient) error
	OAuthClient(id string) (*OAuthClient, error)
	TouchOAuthClient(id string, at time.Time) error
	DeleteOAuthClient(id string) error

	// SaveOAuthAuthRequest creates or replaces the request with r.ID.
	SaveOAuthAuthRequest(r *OAuthAuthRequest) error
	OAuthAuthRequest(id string) (*OAuthAuthRequest, error)
	OAuthAuthRequestByCode(codeHash string) (*OAuthAuthRequest, error)
	DeleteOAuthAuthRequest(id string) error

	CreateOAuthGrant(g *OAuthGrant) error
	OAuthGrant(id string) (*OAuthGrant, error)
	// RevokeOAuthGrants ends grants: by id, or every grant with this ref, or every grant of a
	// client for a subject — whichever of the filter's fields are set (all set fields must match;
	// an empty filter revokes nothing). It returns how many were revoked.
	RevokeOAuthGrants(f OAuthGrantFilter, at time.Time) (int, error)

	CreateOAuthAccessToken(t *OAuthAccessToken) error
	OAuthAccessToken(id string) (*OAuthAccessToken, error)
	DeleteOAuthAccessToken(id string) error

	CreateOAuthRefreshToken(t *OAuthRefreshToken) error
	OAuthRefreshToken(hash string) (*OAuthRefreshToken, error)
	// UseOAuthRefreshToken marks the token used, atomically: of two concurrent calls one wins and
	// the other gets ErrOAuthTokenUsed (as does any later call).
	UseOAuthRefreshToken(hash string, at time.Time) error

	OAuthSigningKeys() ([]OAuthSigningKey, error)
	AddOAuthSigningKey(k *OAuthSigningKey) error

	// DeleteExpiredOAuth removes what can no longer be used: auth requests created before
	// requestsBefore, tokens expired before now, grants revoked or expired before now (with their
	// tokens), and dynamic clients last used (or, never used, created) before clientsBefore.
	DeleteExpiredOAuth(now, requestsBefore, clientsBefore time.Time) error
}

// OAuthGrantFilter selects grants for RevokeOAuthGrants.
type OAuthGrantFilter struct {
	ID       string
	Ref      string
	ClientID string
	Subject  string
}

// Empty reports whether the filter selects nothing.
func (f OAuthGrantFilter) Empty() bool {
	return f.ID == "" && f.Ref == "" && f.ClientID == "" && f.Subject == ""
}
