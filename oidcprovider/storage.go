package oidcprovider

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	authx "github.com/alex-savin/go-auth-x"
)

// storage adapts an authx.OAuthStore to zitadel's op.Storage.
type storage struct {
	p   *Provider
	kek []byte // seals the signing keys at rest (derived from Config.CryptoKey)

	kmu    sync.Mutex
	keys   []signingKey // replaced, never changed in place
	keysAt time.Time    // when keys were read from the store
}

var _ op.Storage = (*storage)(nil)

type ctxKey int

const (
	resourcesKey ctxKey = iota // the request's checked resource indicators ([]string)
	clientKey                  // the client's rate-limit key (string), set by Handler
)

var errNotFound = errors.New("not found")

func (s *storage) st() authx.OAuthStore { return s.p.cfg.Store }

// --- auth requests ---

func (s *storage) CreateAuthRequest(ctx context.Context, ar *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	c, err := s.p.client(ctx, ar.ClientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}
	res, _ := ctx.Value(resourcesKey).([]string)
	scopes := slices.Clone([]string(ar.Scopes))
	// A client that may refresh gets a refresh token without having to know to ask for one.
	if slices.Contains(c.GrantTypes, string(oidc.GrantTypeRefreshToken)) && !slices.Contains(scopes, oidc.ScopeOfflineAccess) {
		scopes = append(scopes, oidc.ScopeOfflineAccess)
	}
	r := &authx.OAuthAuthRequest{
		ID:                  randomID(24),
		ClientID:            ar.ClientID,
		RedirectURI:         ar.RedirectURI,
		State:               ar.State,
		Nonce:               ar.Nonce,
		Scopes:              scopes,
		ResponseType:        string(ar.ResponseType),
		ResponseMode:        string(ar.ResponseMode),
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: string(ar.CodeChallengeMethod),
		Resources:           res,
		Prompt:              ar.Prompt,
		CreatedAt:           time.Now().UTC(),
	}
	// Public clients must use PKCE (OAuth 2.1); S256 only.
	if r.CodeChallenge == "" && c.AuthMethod == string(oidc.AuthMethodNone) {
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge is required")
	}
	if r.CodeChallenge != "" && r.CodeChallengeMethod != string(oidc.CodeChallengeMethodS256) {
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge_method must be S256")
	}
	if err := s.st().SaveOAuthAuthRequest(r); err != nil {
		return nil, err
	}
	return &authRequest{r}, nil
}

func (s *storage) request(id string) (*authx.OAuthAuthRequest, error) {
	r, err := s.st().OAuthAuthRequest(id)
	if err != nil {
		return nil, err
	}
	if time.Since(r.CreatedAt) > authRequestTTL {
		return nil, authx.ErrOAuthNotFound
	}
	return r, nil
}

func (s *storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	r, err := s.request(id)
	if err != nil {
		return nil, err
	}
	return &authRequest{r}, nil
}

// AuthRequestByCode finds the approved request a code was issued for. Single use is enforced when
// the code is exchanged (grantFor), after zitadel has checked the client and PKCE — so a code
// stolen without its verifier can't be burned — and the request is deleted after that exchange.
func (s *storage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	h := hash(code)
	r, err := s.st().OAuthAuthRequestByCode(h)
	if errors.Is(err, authx.ErrOAuthNotFound) {
		s.endReusedCode(h) // exchanged already (its request is gone), or never issued
		return nil, oidc.ErrInvalidGrant().WithDescription("the code is invalid or was already used")
	}
	if err != nil {
		return nil, err
	}
	if !r.Done || time.Since(r.CodeAt) > codeTTL || time.Since(r.CreatedAt) > authRequestTTL {
		return nil, oidc.ErrInvalidGrant().WithDescription("the code has expired")
	}
	return &authRequest{r}, nil
}

// codeGrantID is the ID of the grant a code is exchanged for. Deriving it from the code makes the
// store's unique grant ID the code's single-use guard on every replica, and lets a code presented
// again find the grant it already made.
func codeGrantID(codeHash string) string { return hash("grant:" + codeHash)[:32] }

// endReusedCode ends the grant a code was already exchanged for, if any: a code used twice may have
// been stolen, so the tokens issued for it are revoked (RFC 6749 §4.1.2).
func (s *storage) endReusedCode(codeHash string) {
	id := codeGrantID(codeHash)
	if g, err := s.st().OAuthGrant(id); err == nil && g.RevokedAt == nil {
		s.revokeGrant(id, "authorization code used again")
	}
}

func (s *storage) SaveAuthCode(_ context.Context, id, code string) error {
	r, err := s.request(id)
	if err != nil {
		return err
	}
	r.CodeHash = hash(code)
	r.CodeAt = time.Now().UTC()
	return s.st().SaveOAuthAuthRequest(r)
}

func (s *storage) DeleteAuthRequest(_ context.Context, id string) error {
	return s.st().DeleteOAuthAuthRequest(id)
}

// --- tokens ---

func (s *storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	g, err := s.grantFor(req)
	if err != nil {
		return "", time.Time{}, err
	}
	return s.accessToken(g, req.GetScopes())
}

func (s *storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	var g *authx.OAuthGrant
	var err error
	if current != "" {
		// Rotation: the presented token is used up, atomically; losing the race means it was
		// presented twice, which ends the grant.
		rr, ok := req.(*refreshRequest)
		if !ok {
			return "", "", time.Time{}, op.ErrInvalidRefreshToken
		}
		if err := s.st().UseOAuthRefreshToken(hash(current), time.Now().UTC()); err != nil {
			if errors.Is(err, authx.ErrOAuthTokenUsed) {
				s.revokeGrant(rr.grant.ID, "refresh token replayed")
			}
			return "", "", time.Time{}, op.ErrInvalidRefreshToken
		}
		g = rr.grant
		if err := s.live(g); err != nil {
			return "", "", time.Time{}, err
		}
	} else if g, err = s.grantFor(req); err != nil {
		return "", "", time.Time{}, err
	}
	id, exp, err := s.accessToken(g, req.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}
	// A refresh asking for fewer scopes narrows the access token only: the new refresh token keeps
	// the presented one's scopes (RFC 6749 §6), so a later refresh can ask for them again.
	rscopes := req.GetScopes()
	if rr, ok := req.(*refreshRequest); ok {
		rscopes = rr.token.Scopes
	}
	refresh := "rt_" + randomID(32)
	rexp := capTime(time.Now().UTC().Add(s.p.cfg.RefreshTokenTTL), g.ExpiresAt)
	if err := s.st().CreateOAuthRefreshToken(&authx.OAuthRefreshToken{
		Hash: hash(refresh), GrantID: g.ID, ClientID: g.ClientID, Subject: g.Subject, Scopes: rscopes, ExpiresAt: rexp, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return "", "", time.Time{}, err
	}
	return id, refresh, exp, nil
}

// grantFor turns an approved auth request into its grant (the code exchange); a refresh request
// already has one.
func (s *storage) grantFor(req op.TokenRequest) (*authx.OAuthGrant, error) {
	switch r := req.(type) {
	case *refreshRequest:
		return r.grant, s.live(r.grant)
	case *authRequest:
		if !r.OAuthAuthRequest.Done || r.CodeHash == "" {
			return nil, oidc.ErrInvalidGrant()
		}
		if err := s.userOK(r.Subject); err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		g := &authx.OAuthGrant{
			ID: codeGrantID(r.CodeHash), ClientID: r.ClientID, Subject: r.Subject, Scopes: r.Scopes, Resources: r.Resources,
			Ref: r.Ref, AuthTime: r.AuthTime, CreatedAt: now, ExpiresAt: r.GrantExpiresAt,
		}
		if err := s.st().CreateOAuthGrant(g); err != nil {
			// The ID is taken: this code was exchanged already — racing on another replica, or
			// just before its request was deleted. Used twice, it ends the grant it made.
			if _, gerr := s.st().OAuthGrant(g.ID); gerr == nil {
				s.revokeGrant(g.ID, "authorization code used again")
				return nil, oidc.ErrInvalidGrant().WithDescription("the code was already used")
			}
			return nil, err
		}
		return g, nil
	}
	return nil, oidc.ErrUnsupportedGrantType()
}

// live checks that a grant may still issue tokens: not revoked, not past its end, and its user
// still allowed to sign in.
func (s *storage) live(g *authx.OAuthGrant) error {
	if g.RevokedAt != nil || (!g.ExpiresAt.IsZero() && time.Now().After(g.ExpiresAt)) {
		return op.ErrInvalidRefreshToken
	}
	return s.userOK(g.Subject)
}

// liveToken returns an access token and its grant while the token may be used: issued to subject,
// not expired, and its grant live (see live). Verify, userinfo and introspection all check through
// it, so a revoked grant or a blocked user ends a token everywhere at once.
func (s *storage) liveToken(id, subject string) (*authx.OAuthAccessToken, *authx.OAuthGrant, error) {
	t, err := s.st().OAuthAccessToken(id)
	if err != nil || t.Subject != subject || !time.Now().Before(t.ExpiresAt) {
		return nil, nil, ErrInvalidToken
	}
	g, err := s.st().OAuthGrant(t.GrantID)
	if err != nil || s.live(g) != nil {
		return nil, nil, ErrInvalidToken
	}
	return t, g, nil
}

func (s *storage) userOK(sub string) error {
	if _, err := s.p.cfg.Auth.UserBySub(sub); err != nil {
		return oidc.ErrAccessDenied().WithDescription("this account may not sign in")
	}
	return nil
}

func (s *storage) accessToken(g *authx.OAuthGrant, scopes []string) (string, time.Time, error) {
	now := time.Now().UTC()
	t := &authx.OAuthAccessToken{
		ID: randomID(18), GrantID: g.ID, ClientID: g.ClientID, Subject: g.Subject, Scopes: scopes,
		ExpiresAt: capTime(now.Add(s.p.cfg.AccessTokenTTL), g.ExpiresAt), CreatedAt: now,
	}
	if err := s.st().CreateOAuthAccessToken(t); err != nil {
		return "", time.Time{}, err
	}
	// A client described by a metadata document isn't stored, so there is nothing to touch.
	if !s.p.metadataClient(g.ClientID) {
		if err := s.st().TouchOAuthClient(g.ClientID, now); err != nil {
			s.p.cfg.Logger.Warn("oidcprovider: touching the client failed", "client", g.ClientID, "err", err)
		}
	}
	return t.ID, t.ExpiresAt, nil
}

func capTime(t, limit time.Time) time.Time {
	if !limit.IsZero() && limit.Before(t) {
		return limit
	}
	return t
}

func (s *storage) TokenRequestByRefreshToken(_ context.Context, token string) (op.RefreshTokenRequest, error) {
	t, err := s.st().OAuthRefreshToken(hash(token))
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	if t.UsedAt != nil {
		// A refresh token presented again after its rotation was stolen or replayed (OAuth 2.0
		// Security BCP): end the grant, so neither copy works any longer.
		s.revokeGrant(t.GrantID, "refresh token replayed")
		return nil, op.ErrInvalidRefreshToken
	}
	if time.Now().After(t.ExpiresAt) {
		return nil, op.ErrInvalidRefreshToken
	}
	g, err := s.st().OAuthGrant(t.GrantID)
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	if err := s.live(g); err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshRequest{token: t, grant: g, scopes: t.Scopes}, nil
}

func (s *storage) revokeGrant(id, why string) {
	n, err := s.st().RevokeOAuthGrants(authx.OAuthGrantFilter{ID: id}, time.Now().UTC())
	if err != nil {
		s.p.cfg.Logger.Warn("oidcprovider: revoking a grant failed", "grant", id, "err", err)
		return
	}
	if n > 0 {
		s.p.cfg.Logger.Warn("oidcprovider: grant revoked", "grant", id, "reason", why)
	}
}

func (s *storage) TerminateSession(_ context.Context, userID, clientID string) error {
	if userID == "" || clientID == "" {
		return nil
	}
	_, err := s.st().RevokeOAuthGrants(authx.OAuthGrantFilter{ClientID: clientID, Subject: userID}, time.Now().UTC())
	return err
}

// GetRefreshTokenInfo identifies a refresh token for revocation: "rt:" + its hash.
func (s *storage) GetRefreshTokenInfo(_ context.Context, clientID, token string) (string, string, error) {
	t, err := s.st().OAuthRefreshToken(hash(token))
	if err != nil || t.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return t.Subject, "rt:" + t.Hash, nil
}

// RevokeToken revokes a refresh token (ending its grant) or an access token (that token alone).
// An unknown or foreign token is not an error (RFC 7009).
func (s *storage) RevokeToken(_ context.Context, tokenOrID, userID, clientID string) *oidc.Error {
	userID = unescapeSubject(userID)
	if h, ok := strings.CutPrefix(tokenOrID, "rt:"); ok {
		t, err := s.st().OAuthRefreshToken(h)
		if err == nil && t.ClientID == clientID {
			s.revokeGrant(t.GrantID, "revoked by the client")
		}
		return nil
	}
	t, err := s.st().OAuthAccessToken(tokenOrID)
	if err != nil || t.ClientID != clientID || (userID != "" && t.Subject != userID) {
		return nil
	}
	if err := s.st().DeleteOAuthAccessToken(t.ID); err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}

// --- clients ---

func (s *storage) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	c, err := s.p.client(ctx, id)
	if err != nil {
		return nil, err
	}
	return &client{c: c, p: s.p}, nil
}

func (s *storage) AuthorizeClientIDSecret(ctx context.Context, id, secret string) error {
	c, err := s.p.client(ctx, id)
	if err != nil || c.SecretHash == "" || subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(hash(secret))) != 1 {
		return oidc.ErrInvalidClient()
	}
	return nil
}

// --- claims ---

func (s *storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil // deprecated by zitadel in favour of SetUserinfoFromToken / the request
}

func (s *storage) SetUserinfoFromRequest(ctx context.Context, ui *oidc.UserInfo, req op.IDTokenRequest, scopes []string) error {
	return s.userinfo(ctx, ui, req.GetSubject(), scopes)
}

func (s *storage) SetUserinfoFromToken(ctx context.Context, ui *oidc.UserInfo, tokenID, subject, _ string) error {
	subject = unescapeSubject(subject)
	t, _, err := s.liveToken(tokenID, subject)
	if err != nil {
		return err
	}
	return s.userinfo(ctx, ui, subject, t.Scopes)
}

func (s *storage) userinfo(ctx context.Context, ui *oidc.UserInfo, subject string, scopes []string) error {
	u, err := s.p.cfg.Auth.UserBySub(subject)
	if err != nil {
		return err
	}
	ui.Subject = subject
	if slices.Contains(scopes, oidc.ScopeEmail) {
		ui.Email, ui.EmailVerified = u.Email, oidc.Bool(u.EmailVerified)
	}
	if slices.Contains(scopes, oidc.ScopeProfile) {
		ui.Name = u.Name
	}
	if s.p.cfg.Claims != nil {
		extra, err := s.p.cfg.Claims(ctx, subject, scopes)
		if err != nil {
			return err
		}
		for k, v := range extra {
			ui.AppendClaims(k, v)
		}
	}
	return nil
}

func (s *storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, _ string) error {
	subject = unescapeSubject(subject)
	t, g, err := s.liveToken(tokenID, subject)
	if err != nil {
		return err
	}
	resp.Active = true
	resp.Scope = t.Scopes
	resp.ClientID = t.ClientID
	resp.Subject = subject
	resp.Expiration = oidc.FromTime(t.ExpiresAt)
	resp.IssuedAt = oidc.FromTime(t.CreatedAt)
	resp.Audience = append([]string{t.ClientID}, g.Resources...)
	resp.TokenType = oidc.BearerToken
	return nil
}

func (s *storage) GetPrivateClaimsFromScopes(ctx context.Context, subject, _ string, scopes []string) (map[string]any, error) {
	if s.p.cfg.Claims == nil {
		return nil, nil
	}
	return s.p.cfg.Claims(ctx, subject, scopes)
}

func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("JWT client authentication is not supported")
}

func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("the JWT profile grant is not supported")
}

func (s *storage) Health(context.Context) error { return nil }
