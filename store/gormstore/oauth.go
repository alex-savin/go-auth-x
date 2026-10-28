package gormstore

import (
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the GORM store also satisfies the OAuth provider store.
var _ authx.OAuthStore = (*Store)(nil)

// --- models (the embedded OAuth/OIDC provider's records) ---
//
// Lists ([]string) are stored as JSON text: "null" for nil, "[]" for empty, so both round-trip.
// Optional times (a zero time.Time in the authx record) are stored as NULL, which keeps the
// "expired / unused" predicates in DeleteExpiredOAuth plain portable SQL. Every time is written in
// UTC so SQLite's text comparison orders it correctly.

// OAuthClient is a registered client application (authx.OAuthClient).
type OAuthClient struct {
	ID           string `gorm:"primaryKey"`
	SecretHash   string
	Name         string
	URI          string
	LogoURI      string
	RedirectURIs string `gorm:"type:text"` // JSON list
	GrantTypes   string `gorm:"type:text"` // JSON list
	AuthMethod   string
	Dynamic      bool      `gorm:"index"`
	CreatedAt    time.Time `gorm:"autoCreateTime:false"`
	LastUsedAt   *time.Time
}

func (OAuthClient) TableName() string { return "authx_oauth_clients" }

// OAuthAuthRequest is an authorization request in flight (authx.OAuthAuthRequest).
type OAuthAuthRequest struct {
	ID                  string `gorm:"primaryKey"`
	ClientID            string `gorm:"index"`
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              string `gorm:"type:text"` // JSON list
	ResponseType        string
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	Resources           string `gorm:"type:text"` // JSON list
	Prompt              string `gorm:"type:text"` // JSON list
	Subject             string
	Ref                 string
	GrantExpiresAt      *time.Time
	AuthTime            *time.Time
	Done                bool
	CodeHash            string `gorm:"index"`
	CodeAt              *time.Time
	CreatedAt           time.Time `gorm:"index;autoCreateTime:false"`
}

func (OAuthAuthRequest) TableName() string { return "authx_oauth_auth_requests" }

// OAuthGrant is one approval, the family its tokens belong to (authx.OAuthGrant).
type OAuthGrant struct {
	ID        string `gorm:"primaryKey"`
	ClientID  string `gorm:"index:idx_authx_oauth_grant_client_subject,priority:1"`
	Subject   string `gorm:"index:idx_authx_oauth_grant_client_subject,priority:2"`
	Scopes    string `gorm:"type:text"` // JSON list
	Resources string `gorm:"type:text"` // JSON list
	Ref       string `gorm:"index"`
	AuthTime  *time.Time
	CreatedAt time.Time  `gorm:"autoCreateTime:false"`
	ExpiresAt *time.Time `gorm:"index"` // NULL = no end
	RevokedAt *time.Time `gorm:"index"`
}

func (OAuthGrant) TableName() string { return "authx_oauth_grants" }

// OAuthAccessToken is an issued access token by ID (authx.OAuthAccessToken).
type OAuthAccessToken struct {
	ID        string `gorm:"primaryKey"`
	GrantID   string `gorm:"index"`
	ClientID  string `gorm:"index"`
	Subject   string
	Scopes    string    `gorm:"type:text"` // JSON list
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time `gorm:"autoCreateTime:false"`
}

func (OAuthAccessToken) TableName() string { return "authx_oauth_access_tokens" }

// OAuthRefreshToken is an issued refresh token by hash (authx.OAuthRefreshToken). UsedAt is set
// once, by a conditional UPDATE, so single use holds across replicas.
type OAuthRefreshToken struct {
	Hash      string `gorm:"primaryKey"`
	GrantID   string `gorm:"index"`
	ClientID  string `gorm:"index"`
	Subject   string
	Scopes    string    `gorm:"type:text"` // JSON list
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time `gorm:"autoCreateTime:false"`
	UsedAt    *time.Time
}

func (OAuthRefreshToken) TableName() string { return "authx_oauth_refresh_tokens" }

// OAuthSigningKey is an ID-token signing key (authx.OAuthSigningKey). The private key is stored as
// is; wrap the DB or column with encryption-at-rest if your threat model requires it.
type OAuthSigningKey struct {
	ID         string `gorm:"primaryKey"`
	Algorithm  string
	PrivatePEM []byte
	CreatedAt  time.Time `gorm:"autoCreateTime:false"`
	RetiredAt  *time.Time
}

func (OAuthSigningKey) TableName() string { return "authx_oauth_signing_keys" }

// migrateOAuth is called by New to migrate the OAuth provider tables.
func (s *Store) migrateOAuth() error {
	return s.db.AutoMigrate(&OAuthClient{}, &OAuthAuthRequest{}, &OAuthGrant{},
		&OAuthAccessToken{}, &OAuthRefreshToken{}, &OAuthSigningKey{})
}

// --- conversion helpers ---

func encodeList(v []string) string {
	b, _ := json.Marshal(v) // nil → "null", empty → "[]"; a []string always marshals
	return string(b)
}

func decodeList(s string) []string {
	if s == "" || s == "null" {
		return nil
	}
	var v []string
	if json.Unmarshal([]byte(s), &v) != nil {
		return nil
	}
	return v
}

// optTime maps a zero time to NULL.
func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func fromOptTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return authx.ErrOAuthNotFound
	}
	return err
}

// --- clients ---

func (s *Store) CreateOAuthClient(c *authx.OAuthClient) error {
	return s.db.Create(&OAuthClient{
		ID: c.ID, SecretHash: c.SecretHash, Name: c.Name, URI: c.URI, LogoURI: c.LogoURI,
		RedirectURIs: encodeList(c.RedirectURIs), GrantTypes: encodeList(c.GrantTypes),
		AuthMethod: c.AuthMethod, Dynamic: c.Dynamic,
		CreatedAt: c.CreatedAt.UTC(), LastUsedAt: optTime(c.LastUsedAt),
	}).Error
}

func (s *Store) OAuthClient(id string) (*authx.OAuthClient, error) {
	var r OAuthClient
	if err := s.db.First(&r, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return &authx.OAuthClient{
		ID: r.ID, SecretHash: r.SecretHash, Name: r.Name, URI: r.URI, LogoURI: r.LogoURI,
		RedirectURIs: decodeList(r.RedirectURIs), GrantTypes: decodeList(r.GrantTypes),
		AuthMethod: r.AuthMethod, Dynamic: r.Dynamic,
		CreatedAt: r.CreatedAt, LastUsedAt: fromOptTime(r.LastUsedAt),
	}, nil
}

func (s *Store) TouchOAuthClient(id string, at time.Time) error {
	res := s.db.Model(&OAuthClient{}).Where("id = ?", id).Update("last_used_at", optTime(at))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return authx.ErrOAuthNotFound
	}
	return nil
}

// DeleteOAuthClient removes the client with its auth requests, grants and tokens (idempotent).
func (s *Store) DeleteOAuthClient(id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return deleteClients(tx, tx.Model(&OAuthClient{}).Select("id").Where("id = ?", id))
	})
}

// deleteClients deletes the clients whose ids the subquery selects, and everything issued to them.
func deleteClients(tx *gorm.DB, ids *gorm.DB) error {
	for _, m := range []any{&OAuthAccessToken{}, &OAuthRefreshToken{}, &OAuthGrant{}, &OAuthAuthRequest{}} {
		if err := tx.Where("client_id IN (?)", ids).Delete(m).Error; err != nil {
			return err
		}
	}
	return tx.Where("id IN (?)", ids).Delete(&OAuthClient{}).Error
}

// --- authorization requests ---

func (s *Store) SaveOAuthAuthRequest(r *authx.OAuthAuthRequest) error {
	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&OAuthAuthRequest{
		ID: r.ID, ClientID: r.ClientID, RedirectURI: r.RedirectURI, State: r.State, Nonce: r.Nonce,
		Scopes: encodeList(r.Scopes), ResponseType: r.ResponseType, ResponseMode: r.ResponseMode,
		CodeChallenge: r.CodeChallenge, CodeChallengeMethod: r.CodeChallengeMethod,
		Resources: encodeList(r.Resources), Prompt: encodeList(r.Prompt),
		Subject: r.Subject, Ref: r.Ref, GrantExpiresAt: optTime(r.GrantExpiresAt),
		AuthTime: optTime(r.AuthTime), Done: r.Done,
		CodeHash: r.CodeHash, CodeAt: optTime(r.CodeAt), CreatedAt: r.CreatedAt.UTC(),
	}).Error
}

func (s *Store) OAuthAuthRequest(id string) (*authx.OAuthAuthRequest, error) {
	return s.authRequestWhere("id = ?", id)
}

func (s *Store) OAuthAuthRequestByCode(codeHash string) (*authx.OAuthAuthRequest, error) {
	if codeHash == "" { // a request with no code issued yet must never match
		return nil, authx.ErrOAuthNotFound
	}
	return s.authRequestWhere("code_hash = ?", codeHash)
}

func (s *Store) authRequestWhere(query string, arg string) (*authx.OAuthAuthRequest, error) {
	var r OAuthAuthRequest
	if err := s.db.Where(query, arg).First(&r).Error; err != nil {
		return nil, notFound(err)
	}
	return &authx.OAuthAuthRequest{
		ID: r.ID, ClientID: r.ClientID, RedirectURI: r.RedirectURI, State: r.State, Nonce: r.Nonce,
		Scopes: decodeList(r.Scopes), ResponseType: r.ResponseType, ResponseMode: r.ResponseMode,
		CodeChallenge: r.CodeChallenge, CodeChallengeMethod: r.CodeChallengeMethod,
		Resources: decodeList(r.Resources), Prompt: decodeList(r.Prompt),
		Subject: r.Subject, Ref: r.Ref, GrantExpiresAt: fromOptTime(r.GrantExpiresAt),
		AuthTime: fromOptTime(r.AuthTime), Done: r.Done,
		CodeHash: r.CodeHash, CodeAt: fromOptTime(r.CodeAt), CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) DeleteOAuthAuthRequest(id string) error {
	return s.db.Delete(&OAuthAuthRequest{}, "id = ?", id).Error
}

// --- grants ---

func (s *Store) CreateOAuthGrant(g *authx.OAuthGrant) error {
	return s.db.Create(&OAuthGrant{
		ID: g.ID, ClientID: g.ClientID, Subject: g.Subject,
		Scopes: encodeList(g.Scopes), Resources: encodeList(g.Resources), Ref: g.Ref,
		AuthTime: optTime(g.AuthTime), CreatedAt: g.CreatedAt.UTC(),
		ExpiresAt: optTime(g.ExpiresAt), RevokedAt: utcPtr(g.RevokedAt),
	}).Error
}

func (s *Store) OAuthGrant(id string) (*authx.OAuthGrant, error) {
	var r OAuthGrant
	if err := s.db.First(&r, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return &authx.OAuthGrant{
		ID: r.ID, ClientID: r.ClientID, Subject: r.Subject,
		Scopes: decodeList(r.Scopes), Resources: decodeList(r.Resources), Ref: r.Ref,
		AuthTime: fromOptTime(r.AuthTime), CreatedAt: r.CreatedAt,
		ExpiresAt: fromOptTime(r.ExpiresAt), RevokedAt: r.RevokedAt,
	}, nil
}

func (s *Store) RevokeOAuthGrants(f authx.OAuthGrantFilter, at time.Time) (int, error) {
	if f.Empty() {
		return 0, nil
	}
	q := s.db.Model(&OAuthGrant{}).Where("revoked_at IS NULL")
	if f.ID != "" {
		q = q.Where("id = ?", f.ID)
	}
	if f.Ref != "" {
		q = q.Where("ref = ?", f.Ref)
	}
	if f.ClientID != "" {
		q = q.Where("client_id = ?", f.ClientID)
	}
	if f.Subject != "" {
		q = q.Where("subject = ?", f.Subject)
	}
	res := q.Update("revoked_at", at.UTC())
	return int(res.RowsAffected), res.Error
}

// --- access tokens ---

func (s *Store) CreateOAuthAccessToken(t *authx.OAuthAccessToken) error {
	return s.db.Create(&OAuthAccessToken{
		ID: t.ID, GrantID: t.GrantID, ClientID: t.ClientID, Subject: t.Subject,
		Scopes: encodeList(t.Scopes), ExpiresAt: t.ExpiresAt.UTC(), CreatedAt: t.CreatedAt.UTC(),
	}).Error
}

func (s *Store) OAuthAccessToken(id string) (*authx.OAuthAccessToken, error) {
	var r OAuthAccessToken
	if err := s.db.First(&r, "id = ?", id).Error; err != nil {
		return nil, notFound(err)
	}
	return &authx.OAuthAccessToken{
		ID: r.ID, GrantID: r.GrantID, ClientID: r.ClientID, Subject: r.Subject,
		Scopes: decodeList(r.Scopes), ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) DeleteOAuthAccessToken(id string) error {
	return s.db.Delete(&OAuthAccessToken{}, "id = ?", id).Error
}

// --- refresh tokens ---

func (s *Store) CreateOAuthRefreshToken(t *authx.OAuthRefreshToken) error {
	return s.db.Create(&OAuthRefreshToken{
		Hash: t.Hash, GrantID: t.GrantID, ClientID: t.ClientID, Subject: t.Subject,
		Scopes: encodeList(t.Scopes), ExpiresAt: t.ExpiresAt.UTC(), CreatedAt: t.CreatedAt.UTC(),
		UsedAt: utcPtr(t.UsedAt),
	}).Error
}

func (s *Store) OAuthRefreshToken(hash string) (*authx.OAuthRefreshToken, error) {
	var r OAuthRefreshToken
	if err := s.db.First(&r, "hash = ?", hash).Error; err != nil {
		return nil, notFound(err)
	}
	return &authx.OAuthRefreshToken{
		Hash: r.Hash, GrantID: r.GrantID, ClientID: r.ClientID, Subject: r.Subject,
		Scopes: decodeList(r.Scopes), ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt, UsedAt: r.UsedAt,
	}, nil
}

// UseOAuthRefreshToken marks the token used with one conditional UPDATE: the database serializes
// concurrent exchanges, so exactly one sees a row affected. A miss is then told apart (absent vs used).
func (s *Store) UseOAuthRefreshToken(hash string, at time.Time) error {
	res := s.db.Model(&OAuthRefreshToken{}).Where("hash = ? AND used_at IS NULL", hash).
		Update("used_at", at.UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 1 {
		return nil
	}
	var n int64
	if err := s.db.Model(&OAuthRefreshToken{}).Where("hash = ?", hash).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return authx.ErrOAuthNotFound
	}
	return authx.ErrOAuthTokenUsed
}

// --- signing keys ---

// OAuthSigningKeys returns every key, oldest first.
func (s *Store) OAuthSigningKeys() ([]authx.OAuthSigningKey, error) {
	var rows []OAuthSigningKey
	if err := s.db.Order("created_at asc, id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]authx.OAuthSigningKey, 0, len(rows))
	for i := range rows {
		out = append(out, authx.OAuthSigningKey{
			ID: rows[i].ID, Algorithm: rows[i].Algorithm, PrivatePEM: rows[i].PrivatePEM,
			CreatedAt: rows[i].CreatedAt, RetiredAt: rows[i].RetiredAt,
		})
	}
	return out, nil
}

// AddOAuthSigningKey adds the key, or replaces the one with k.ID — the interface has no separate
// retire call, so retiring a key is re-adding it with RetiredAt set.
func (s *Store) AddOAuthSigningKey(k *authx.OAuthSigningKey) error {
	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&OAuthSigningKey{
		ID: k.ID, Algorithm: k.Algorithm, PrivatePEM: k.PrivatePEM,
		CreatedAt: k.CreatedAt.UTC(), RetiredAt: utcPtr(k.RetiredAt),
	}).Error
}

// --- cleanup ---

func (s *Store) DeleteExpiredOAuth(now, requestsBefore, clientsBefore time.Time) error {
	now, requestsBefore, clientsBefore = now.UTC(), requestsBefore.UTC(), clientsBefore.UTC()
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&OAuthAuthRequest{}, "created_at < ?", requestsBefore).Error; err != nil {
			return err
		}
		if err := tx.Delete(&OAuthAccessToken{}, "expires_at < ?", now).Error; err != nil {
			return err
		}
		if err := tx.Delete(&OAuthRefreshToken{}, "expires_at < ?", now).Error; err != nil {
			return err
		}
		// Dead grants (revoked, or past their end) take their tokens with them.
		dead := tx.Model(&OAuthGrant{}).Select("id").
			Where("revoked_at < ? OR (expires_at IS NOT NULL AND expires_at < ?)", now, now)
		for _, m := range []any{&OAuthAccessToken{}, &OAuthRefreshToken{}} {
			if err := tx.Where("grant_id IN (?)", dead).Delete(m).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("revoked_at < ? OR (expires_at IS NOT NULL AND expires_at < ?)", now, now).
			Delete(&OAuthGrant{}).Error; err != nil {
			return err
		}
		// Stale dynamic clients: last used (NULL = never, so registration time) before clientsBefore.
		stale := tx.Model(&OAuthClient{}).Select("id").
			Where("dynamic = ? AND COALESCE(last_used_at, created_at) < ?", true, clientsBefore)
		return deleteClients(tx, stale)
	})
}
