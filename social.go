package authx

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
)

// enableSocial builds the Google/GitHub OAuth configs from the env-provided credentials. Google
// is an OIDC provider (verified-email id_token); GitHub is plain OAuth2 + REST. Best-effort: a
// provider stays nil/off if its credentials are unset or (Google) discovery fails.
func (a *Authenticator) enableSocial(ctx context.Context) {
	if a.cfg.GoogleClientID != "" && a.cfg.GoogleClientSecret != "" {
		if p, err := oidc.NewProvider(ctx, "https://accounts.google.com"); err == nil {
			a.googleVerifier = p.Verifier(&oidc.Config{ClientID: a.cfg.GoogleClientID})
			a.googleOAuth = &oauth2.Config{
				ClientID: a.cfg.GoogleClientID, ClientSecret: a.cfg.GoogleClientSecret,
				Endpoint: p.Endpoint(), RedirectURL: a.socialRedirect("google"),
				Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
			}
		}
	}
	if a.cfg.GitHubClientID != "" && a.cfg.GitHubClientSecret != "" {
		a.githubOAuth = &oauth2.Config{
			ClientID: a.cfg.GitHubClientID, ClientSecret: a.cfg.GitHubClientSecret,
			Endpoint: github.Endpoint, RedirectURL: a.socialRedirect("github"),
			Scopes: []string{"read:user", "user:email"},
		}
	}
	if a.cfg.FacebookClientID != "" && a.cfg.FacebookClientSecret != "" {
		a.facebookOAuth = &oauth2.Config{
			ClientID: a.cfg.FacebookClientID, ClientSecret: a.cfg.FacebookClientSecret,
			Endpoint: facebook.Endpoint, RedirectURL: a.socialRedirect("facebook"),
			Scopes: []string{"email", "public_profile"},
		}
	}
	a.enableApple(ctx)      // Sign in with Apple (OIDC; secret is a signed JWT — see social_apple.go)
	a.enableDiscord()       // Discord (OAuth2 + REST — see social_oidc.go)
	a.enableOIDCSocial(ctx) // Microsoft/Entra + any Config.SocialOIDC (generic OIDC — see social_oidc.go)
}

func (a *Authenticator) socialRedirect(provider string) string {
	return a.baseURL() + "/auth/social/" + provider + "/callback"
}

func (a *Authenticator) socialConfigured(provider string) bool { return a.socialOAuth(provider) != nil }

func (a *Authenticator) socialOAuth(provider string) *oauth2.Config {
	switch provider {
	case "google":
		return a.googleOAuth
	case "github":
		return a.githubOAuth
	case "facebook":
		return a.facebookOAuth
	case "apple":
		return a.appleOAuth
	case "discord":
		return a.discordOAuth
	}
	if p := a.oidcSocial[provider]; p != nil {
		return p.oauth
	}
	return nil
}

// SocialLogin (GET /auth/social/:provider/login) starts the provider's Authorization Code + PKCE
// flow, stashing state/nonce/verifier/next in the signed flow cookie (same machinery as OIDC).
func (a *Authenticator) SocialLogin(c *reqCtx) {
	provider := c.Param("provider")
	oc := a.socialOAuth(provider)
	if oc == nil {
		c.JSON(http.StatusNotFound, H{"error": "provider not enabled"})
		return
	}
	state, nonce, verifier := randToken(), randToken(), oauth2.GenerateVerifier()
	flow, err := mintFlow(a.cfg.SessionSecret, flowClaims{State: state, Nonce: nonce, Verifier: verifier, Next: sanitizeNext(c.Query("next"))}, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "login init failed"})
		return
	}
	if provider == "apple" {
		a.setFlowCookieCrossSite(c, flow) // Apple posts its callback cross-site; a Lax cookie wouldn't be sent
	} else {
		a.setCookie(c, flowCookie, flow, int(flowTTL/time.Second))
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if provider == "google" || provider == "apple" || a.oidcSocial[provider] != nil {
		opts = append(opts, oidc.Nonce(nonce)) // OIDC providers — bind the id_token to our nonce
	}
	if provider == "apple" {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	c.Redirect(http.StatusFound, oc.AuthCodeURL(state, opts...))
}

// SocialCallback (GET /auth/social/:provider/callback) verifies state, exchanges the code, reads
// the provider-verified identity, links/creates the local user, and signs them in.
func (a *Authenticator) SocialCallback(c *reqCtx) {
	provider := c.Param("provider")
	oc := a.socialOAuth(provider)
	if oc == nil {
		c.JSON(http.StatusNotFound, H{"error": "provider not enabled"})
		return
	}
	if a.creds == nil { // social login links/creates local users; without a credential store it can't proceed
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in unavailable"})
		return
	}
	ctx := c.Request.Context()
	flowTok, _ := c.Cookie(flowCookie)
	fc, err := parseFlowMulti(a.verifySecrets(), flowTok)
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "login session expired — try again"})
		return
	}
	a.clearCookie(c, flowCookie)
	// FormValue reads the query (GET providers) OR the posted form (Apple's form_post).
	if errMsg := c.Request.FormValue("error"); errMsg != "" {
		c.JSON(http.StatusUnauthorized, H{"error": "identity provider: " + errMsg})
		return
	}
	if !ctEqual(c.Request.FormValue("state"), fc.State) {
		c.JSON(http.StatusBadRequest, H{"error": "state mismatch"})
		return
	}
	xc, xerr := a.exchangeConfig(provider, oc) // Apple needs a freshly-signed client-secret JWT
	if xerr != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "provider secret unavailable"})
		return
	}
	tok, err := xc.Exchange(ctx, c.Request.FormValue("code"), oauth2.VerifierOption(fc.Verifier))
	if err != nil {
		c.JSON(http.StatusBadGateway, H{"error": "token exchange failed"})
		return
	}

	var subject, email, name string
	switch provider {
	case "google":
		rawID, ok := tok.Extra("id_token").(string)
		if !ok || a.googleVerifier == nil {
			c.JSON(http.StatusBadGateway, H{"error": "no id_token in response"})
			return
		}
		idt, err := a.googleVerifier.Verify(ctx, rawID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, H{"error": "id_token verification failed"})
			return
		}
		if !ctEqual(idt.Nonce, fc.Nonce) {
			c.JSON(http.StatusUnauthorized, H{"error": "nonce mismatch"})
			return
		}
		var cl struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
			AZP           string `json:"azp"`
		}
		_ = idt.Claims(&cl)
		if err := verifyAZP(idt.Audience, cl.AZP, a.cfg.GoogleClientID); err != nil {
			c.JSON(http.StatusUnauthorized, H{"error": "id_token not authorized for this client"})
			return
		}
		if !cl.EmailVerified || cl.Email == "" {
			c.JSON(http.StatusForbidden, H{"error": "your Google email is not verified"})
			return
		}
		subject, email, name = idt.Subject, cl.Email, cl.Name
	case "github":
		subject, email, name, err = a.githubIdentity(ctx, oc, tok)
		if err != nil {
			c.JSON(http.StatusForbidden, H{"error": err.Error()})
			return
		}
	case "facebook":
		subject, email, name, err = a.facebookIdentity(ctx, oc, tok)
		if err != nil {
			c.JSON(http.StatusForbidden, H{"error": err.Error()})
			return
		}
	case "apple":
		subject, email, name, err = a.appleIdentity(ctx, tok, fc.Nonce, c.Request.FormValue("user"))
		if err != nil {
			c.JSON(http.StatusForbidden, H{"error": err.Error()})
			return
		}
	case "discord":
		subject, email, name, err = a.discordIdentity(ctx, oc, tok)
		if err != nil {
			c.JSON(http.StatusForbidden, H{"error": err.Error()})
			return
		}
	default: // a generic OIDC provider (Microsoft/Entra or a Config.SocialOIDC entry)
		p := a.oidcSocial[provider]
		if p == nil {
			c.JSON(http.StatusNotFound, H{"error": "provider not enabled"})
			return
		}
		subject, email, name, err = oidcSocialIdentity(ctx, p.verifier, p.clientID, tok, fc.Nonce, p.assumeVerified)
		if err != nil {
			c.JSON(http.StatusForbidden, H{"error": err.Error()}) // 403, matching the other providers' identity failures
			return
		}
	}

	au, err := a.resolveSocialUser(provider, subject, email, name)
	if err != nil {
		if errors.Is(err, ErrEmailConflict) {
			c.JSON(http.StatusConflict, H{"error": "an account already exists for this email — sign in with your existing method first, then link " + provider})
			return
		}
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	if blocked, msg := au.loginBlocked(); blocked {
		c.JSON(http.StatusForbidden, H{"error": msg})
		return
	}
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), provider, "login", true, "")
	tfr, err := a.completeLogin(c, Identity{Subject: au.Sub, Email: au.Email, Name: au.Name, EmailVerified: true}, false, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	if tfr {
		c.Redirect(http.StatusFound, withMFAMarker(fc.Next))
		return
	}
	c.Redirect(http.StatusFound, fc.Next)
}

// resolveSocialUser maps a provider identity to a local user. Natural key first (provider,
// subject); else link to an existing VERIFIED-email user (safe — the provider proved the email);
// else create a new user. An unverified, non-bootstrap email squatter is refused (no takeover).
func (a *Authenticator) resolveSocialUser(provider, subject, email, name string) (*AuthUser, error) {
	if u, err := a.creds.UserByOAuth(provider, subject); err == nil {
		return u, nil
	} else if !errors.Is(err, ErrNoUser) {
		return nil, err
	}
	if u, err := a.creds.UserByEmail(email); err == nil {
		if u.EmailVerified {
			if err := a.creds.LinkOAuth(u.ID, provider, subject, email); err != nil {
				return nil, err
			}
			return u, nil
		}
		// Unverified squatter on a provider-verified email. With a directory wired, reclaim it
		// (the verified social login wins); otherwise refuse rather than risk a takeover.
		if a.dir == nil {
			return nil, ErrEmailConflict
		}
		nu, rerr := a.dir.UpsertExternalUser("social:"+provider+":"+subject, email, name, true)
		if rerr != nil {
			return nil, rerr
		}
		_ = a.creds.LinkOAuth(nu.ID, provider, subject, email)
		return nu, nil
	} else if !errors.Is(err, ErrNoUser) {
		return nil, err
	}
	u, err := a.creds.CreateLocalUser(email, name)
	if err != nil {
		return nil, err
	}
	if err := a.creds.LinkOAuth(u.ID, provider, subject, email); err != nil {
		return nil, err
	}
	_ = a.creds.SetEmailVerified(u.ID, true) // the provider verified the address
	return u, nil
}

// githubIdentity fetches the GitHub user id (stable subject) + a primary, verified email.
func (a *Authenticator) githubIdentity(ctx context.Context, oc *oauth2.Config, tok *oauth2.Token) (subject, email, name string, err error) {
	client := oc.Client(ctx, tok)
	var profile struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Login string `json:"login"`
	}
	if err = getJSON(ctx, client, "https://api.github.com/user", &profile); err != nil {
		return "", "", "", errors.New("could not read your GitHub profile")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err = getJSON(ctx, client, "https://api.github.com/user/emails", &emails); err != nil {
		return "", "", "", errors.New("could not read your GitHub emails")
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			name = profile.Name
			if name == "" {
				name = profile.Login
			}
			return strconv.FormatInt(profile.ID, 10), e.Email, name, nil
		}
	}
	return "", "", "", errors.New("your GitHub account has no primary, verified email")
}

// facebookIdentity fetches the Facebook user id (stable subject), name, and email via the Graph API.
// Facebook verifies account emails, so a returned email is treated as verified. An appsecret_proof
// (HMAC of the token with the app secret) binds the call to our app, per Facebook's guidance.
func (a *Authenticator) facebookIdentity(ctx context.Context, oc *oauth2.Config, tok *oauth2.Token) (subject, email, name string, err error) {
	proof := hmacSHA256Hex(oc.ClientSecret, tok.AccessToken)
	client := oc.Client(ctx, tok)
	var me struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	url := "https://graph.facebook.com/v19.0/me?fields=id,name,email&appsecret_proof=" + proof
	if err = getJSONPlain(ctx, client, url, &me); err != nil {
		return "", "", "", errors.New("could not read your Facebook profile")
	}
	if me.ID == "" {
		return "", "", "", errors.New("could not read your Facebook profile")
	}
	if me.Email == "" {
		return "", "", "", errors.New("your Facebook account has no email — grant email access when signing in")
	}
	return me.ID, me.Email, me.Name, nil
}

func hmacSHA256Hex(key, msg string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// getJSONPlain GETs url and decodes the JSON body (for non-GitHub providers, no special Accept).
func getJSONPlain(ctx context.Context, client *http.Client, url string, dest any) error {
	return getJSONWithAccept(ctx, client, url, "", dest)
}

// getJSON GETs url with GitHub's Accept header and decodes the JSON body.
func getJSON(ctx context.Context, client *http.Client, url string, dest any) error {
	return getJSONWithAccept(ctx, client, url, "application/vnd.github+json", dest)
}

// getJSONWithAccept is the shared GET+decode used by both helpers (optional Accept header).
func getJSONWithAccept(ctx context.Context, client *http.Client, url, accept string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("provider returned " + res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxRequestBody)).Decode(dest)
}
