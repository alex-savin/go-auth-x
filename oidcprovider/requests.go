package oidcprovider

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	authx "github.com/alex-savin/go-auth-x"
)

// authRequest is a stored authorization request as zitadel sees it.
type authRequest struct{ *authx.OAuthAuthRequest }

var _ op.AuthRequest = (*authRequest)(nil)

func (r *authRequest) GetID() string           { return r.ID }
func (r *authRequest) GetACR() string          { return "" }
func (r *authRequest) GetAMR() []string        { return nil }
func (r *authRequest) GetAudience() []string   { return []string{r.ClientID} }
func (r *authRequest) GetAuthTime() time.Time  { return r.AuthTime }
func (r *authRequest) GetClientID() string     { return r.ClientID }
func (r *authRequest) GetNonce() string        { return r.Nonce }
func (r *authRequest) GetRedirectURI() string  { return r.RedirectURI }
func (r *authRequest) GetScopes() []string     { return r.Scopes }
func (r *authRequest) GetState() string        { return r.State }
func (r *authRequest) GetSubject() string      { return r.Subject }
func (r *authRequest) Done() bool              { return r.OAuthAuthRequest.Done }
func (r *authRequest) GetResponseType() oidc.ResponseType {
	return oidc.ResponseType(r.ResponseType)
}
func (r *authRequest) GetResponseMode() oidc.ResponseMode {
	return oidc.ResponseMode(r.ResponseMode)
}
func (r *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if r.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: r.CodeChallenge, Method: oidc.CodeChallengeMethod(r.CodeChallengeMethod)}
}

// refreshRequest is a refresh token being exchanged, with its grant.
type refreshRequest struct {
	token  *authx.OAuthRefreshToken
	grant  *authx.OAuthGrant
	scopes []string
}

var _ op.RefreshTokenRequest = (*refreshRequest)(nil)

func (r *refreshRequest) GetAMR() []string       { return nil }
func (r *refreshRequest) GetAudience() []string  { return []string{r.grant.ClientID} }
func (r *refreshRequest) GetAuthTime() time.Time { return r.grant.AuthTime }
func (r *refreshRequest) GetClientID() string    { return r.grant.ClientID }
func (r *refreshRequest) GetScopes() []string    { return r.scopes }
func (r *refreshRequest) GetSubject() string     { return r.grant.Subject }

// SetCurrentScopes narrows the scopes (a refresh may ask for fewer, never more).
func (r *refreshRequest) SetCurrentScopes(scopes []string) {
	var out []string
	for _, s := range scopes {
		if slices.Contains(r.token.Scopes, s) {
			out = append(out, s)
		}
	}
	r.scopes = out
}

// client is a stored client as zitadel sees it.
type client struct {
	c *authx.OAuthClient
	p *Provider
}

var _ op.Client = (*client)(nil)

func (c *client) GetID() string                    { return c.c.ID }
func (c *client) RedirectURIs() []string           { return c.c.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string { return nil }
func (c *client) AuthMethod() oidc.AuthMethod      { return oidc.AuthMethod(c.c.AuthMethod) }
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *client) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(c.c.GrantTypes))
	for _, g := range c.c.GrantTypes {
		out = append(out, oidc.GrantType(g))
	}
	return out
}
func (c *client) LoginURL(id string) string                  { return c.p.prefix + "/login?id=" + url.QueryEscape(id) }
func (c *client) AccessTokenType() op.AccessTokenType        { return op.AccessTokenTypeBearer }
func (c *client) IDTokenLifetime() time.Duration             { return idTokenTTL }
func (c *client) DevMode() bool                              { return c.p.cfg.Insecure }
func (c *client) IDTokenUserinfoClaimsAssertion() bool       { return false }
func (c *client) ClockSkew() time.Duration                   { return 0 }
func (c *client) IsScopeAllowed(scope string) bool           { return slices.Contains(c.p.cfg.Scopes, scope) }
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

// ApplicationType is native when a redirect goes to the device itself (a loopback address or an
// app's own scheme), so a loopback redirect may use any port (RFC 8252); otherwise web.
func (c *client) ApplicationType() op.ApplicationType {
	for _, u := range c.c.RedirectURIs {
		if _, loop := op.HTTPLoopbackOrLocalhost(u); loop || !(strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) {
			return op.ApplicationTypeNative
		}
	}
	return op.ApplicationTypeWeb
}
