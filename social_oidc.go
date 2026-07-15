package authx

import (
	"context"
	"errors"
	"log"
	"sort"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// isMultiTenantMicrosoft reports whether the tenant is one of Entra's multi-tenant meta-endpoints, which
// accept id_tokens from any tenant and therefore cannot vouch for the token's email (nOAuth).
func isMultiTenantMicrosoft(tenant string) bool {
	switch strings.ToLower(strings.TrimSpace(tenant)) {
	case "", "common", "organizations", "consumers":
		return true
	}
	return false
}

// oidcProvider is a generic OIDC social provider: an OAuth2 config plus an id_token verifier. It
// backs Microsoft/Entra and any Config.SocialOIDC entry, reusing the exact Google sign-in path.
type oidcProvider struct {
	oauth          *oauth2.Config
	verifier       *oidc.IDTokenVerifier
	clientID       string
	assumeVerified bool // trust the token email when the provider omits email_verified
}

// enableOIDCSocial registers every configured generic OIDC provider — the Microsoft/Entra preset
// plus any Config.SocialOIDC entries. Best-effort: a provider stays off if it's misconfigured, its
// slug collides with a built-in/duplicate, or discovery fails.
func (a *Authenticator) enableOIDCSocial(ctx context.Context) {
	providers := append([]SocialOIDCProvider(nil), a.cfg.SocialOIDC...)

	// Microsoft / Entra ID preset over the same generic OIDC machinery.
	if a.cfg.MicrosoftClientID != "" && a.cfg.MicrosoftClientSecret != "" {
		tenant := a.cfg.MicrosoftTenant
		if tenant == "" {
			tenant = "common"
		}
		// nOAuth guard: a MULTI-TENANT endpoint (common/organizations/consumers or unset) accepts
		// id_tokens from ANY Entra tenant, so the token's email is attacker-controllable — an attacker's
		// own tenant can set a user's `mail` to a victim's address. Only trust an ABSENT email_verified
		// (assume-verified) when a single concrete tenant/domain is pinned, so the org owns its addresses.
		// In multi-tenant mode we force strict verification; since Entra omits email_verified, logins there
		// are refused until the operator pins a tenant (MICROSOFT_TENANT) — the safe posture.
		assumeVerified := !a.cfg.MicrosoftStrictEmailVerified && !isMultiTenantMicrosoft(tenant)
		if a.cfg.MicrosoftTenant == "" || isMultiTenantMicrosoft(a.cfg.MicrosoftTenant) {
			log.Printf("authx: Microsoft login is configured for a multi-tenant endpoint (%q); token email is not trusted there — set MICROSOFT_TENANT to a single tenant/domain to enable email-based sign-in.", tenant)
		}
		providers = append(providers, SocialOIDCProvider{
			Name:           "microsoft",
			Issuer:         "https://login.microsoftonline.com/" + tenant + "/v2.0",
			ClientID:       a.cfg.MicrosoftClientID,
			ClientSecret:   a.cfg.MicrosoftClientSecret,
			AssumeVerified: assumeVerified,
		})
	}

	for _, sp := range providers {
		name := strings.ToLower(strings.TrimSpace(sp.Name))
		if name == "" || sp.Issuer == "" || sp.ClientID == "" || sp.ClientSecret == "" {
			continue
		}
		if a.socialOAuth(name) != nil { // don't shadow a built-in (google/…) or a duplicate slug
			continue
		}
		p, err := oidc.NewProvider(ctx, strings.TrimRight(sp.Issuer, "/"))
		if err != nil {
			continue
		}
		scopes := sp.Scopes
		if len(scopes) == 0 {
			scopes = []string{oidc.ScopeOpenID, "email", "profile"}
		}
		if a.oidcSocial == nil {
			a.oidcSocial = map[string]*oidcProvider{}
		}
		a.oidcSocial[name] = &oidcProvider{
			oauth: &oauth2.Config{
				ClientID: sp.ClientID, ClientSecret: sp.ClientSecret,
				Endpoint: p.Endpoint(), RedirectURL: a.socialRedirect(name), Scopes: scopes,
			},
			verifier:       p.Verifier(&oidc.Config{ClientID: sp.ClientID}),
			clientID:       sp.ClientID,
			assumeVerified: sp.AssumeVerified,
		}
	}
}

// oidcSocialIdentity verifies an OIDC id_token from the token response and returns the
// provider-verified identity. It enforces nonce, azp, and email_verified — unless assumeVerified is
// set, in which case a present token email (or an email-shaped preferred_username) is trusted when
// the provider omits the claim (e.g. Entra, whose tenant owns the address).
func oidcSocialIdentity(ctx context.Context, verifier *oidc.IDTokenVerifier, clientID string, tok *oauth2.Token, wantNonce string, assumeVerified bool) (subject, email, name string, err error) {
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || verifier == nil {
		return "", "", "", errors.New("no id_token in the provider response")
	}
	idt, verr := verifier.Verify(ctx, rawID)
	if verr != nil {
		return "", "", "", errors.New("id_token verification failed")
	}
	if !ctEqual(idt.Nonce, wantNonce) {
		return "", "", "", errors.New("nonce mismatch")
	}
	var cl struct {
		Email             string `json:"email"`
		EmailVerified     *bool  `json:"email_verified"` // pointer: distinguish absent from false
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		AZP               string `json:"azp"`
	}
	_ = idt.Claims(&cl)
	if err := verifyAZP(idt.Audience, cl.AZP, clientID); err != nil {
		return "", "", "", errors.New("id_token not authorized for this client")
	}
	email = cl.Email
	verified := cl.EmailVerified != nil && *cl.EmailVerified
	// assumeVerified only fills in for an ABSENT claim (the pointer is nil); an explicit
	// email_verified:false is always honored — a provider that says "not verified" is never trusted.
	if cl.EmailVerified == nil && assumeVerified {
		if email == "" && strings.Contains(cl.PreferredUsername, "@") {
			email = cl.PreferredUsername // Entra puts the UPN (an email) here when email is absent
		}
		verified = email != ""
	}
	if email == "" || !verified {
		return "", "", "", errors.New("your email is not verified with this provider")
	}
	name = cl.Name
	if name == "" {
		name = cl.PreferredUsername
	}
	return idt.Subject, email, name, nil
}

// enableDiscord builds the Discord OAuth2 config (Discord is OAuth2 + REST, not OIDC).
func (a *Authenticator) enableDiscord() {
	if a.cfg.DiscordClientID == "" || a.cfg.DiscordClientSecret == "" {
		return
	}
	a.discordOAuth = &oauth2.Config{
		ClientID: a.cfg.DiscordClientID, ClientSecret: a.cfg.DiscordClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
		RedirectURL: a.socialRedirect("discord"),
		Scopes:      []string{"identify", "email"},
	}
}

// discordIdentity fetches the Discord user id (stable subject), display name, and a verified email.
func (a *Authenticator) discordIdentity(ctx context.Context, oc *oauth2.Config, tok *oauth2.Token) (subject, email, name string, err error) {
	client := oc.Client(ctx, tok)
	var me struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		GlobalName string `json:"global_name"`
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
	}
	if err = getJSONPlain(ctx, client, "https://discord.com/api/users/@me", &me); err != nil {
		return "", "", "", errors.New("could not read your Discord profile")
	}
	if me.ID == "" {
		return "", "", "", errors.New("could not read your Discord profile")
	}
	if me.Email == "" || !me.Verified {
		return "", "", "", errors.New("your Discord account has no verified email")
	}
	name = me.GlobalName
	if name == "" {
		name = me.Username
	}
	return me.ID, me.Email, name, nil
}

// anySocialConfigured reports whether at least one social provider is enabled (gates the routes).
func (a *Authenticator) anySocialConfigured() bool {
	return a.socialConfigured("google") || a.socialConfigured("github") ||
		a.socialConfigured("facebook") || a.socialConfigured("apple") ||
		a.socialConfigured("discord") || len(a.oidcSocial) > 0
}

// enabledSocialProviders returns the sorted slugs of every enabled social provider (built-ins that
// are configured plus every generic OIDC provider), for the /auth/config discovery response.
func (a *Authenticator) enabledSocialProviders() []string {
	var out []string
	for _, p := range []string{"google", "github", "facebook", "apple", "discord"} {
		if a.socialConfigured(p) {
			out = append(out, p)
		}
	}
	for name := range a.oidcSocial {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
