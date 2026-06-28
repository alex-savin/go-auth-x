package authx

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// ctEqual is a constant-time string compare, used for the OAuth state and OIDC nonce checks so
// the callback doesn't leak a timing side-channel on these single-use anti-CSRF/replay values
// (OAuth 2.0 Security BCP / RFC 9700).
func ctEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Register attaches the /auth/* routes. Safe to call when disabled — the handlers
// short-circuit, and the middleware never gates anything anyway. The consuming app owns its
// own login/landing UI pages; this module only serves the JSON + ceremony endpoints.
func (a *Authenticator) Register(r gin.IRouter) {
	g := r.Group("/auth")
	g.GET("/login", a.Login)       // OIDC: start the Authorization Code + PKCE flow
	g.GET("/callback", a.Callback) // OIDC: redirect target
	g.GET("/logout", a.Logout)
	g.GET("/me", a.Me)
	g.GET("/config", a.AuthConfig) // public: which sign-in methods are available
	// In-app auth methods (password/passkey/email), registered only when local auth is on.
	// OIDC routes above keep working alongside them.
	if a.LocalEnabled() {
		g.POST("/password/signup", a.PasswordSignup)
		g.POST("/password/login", a.PasswordLogin)
		g.POST("/password/reset/request", a.PasswordResetRequest)
		g.POST("/password/reset/confirm", a.PasswordResetConfirm)
		g.POST("/email/request", a.EmailRequest)
		g.GET("/email/login", a.EmailLogin)
		g.GET("/email/verify", a.EmailVerify)
		// Passkeys (WebAuthn) — register is session-gated; login is discoverable (QR-capable).
		g.POST("/webauthn/register/begin", a.WebauthnRegisterBegin)
		g.POST("/webauthn/register/finish", a.WebauthnRegisterFinish)
		g.POST("/webauthn/login/begin", a.WebauthnLoginBegin)
		g.POST("/webauthn/login/finish", a.WebauthnLoginFinish)
		// Self-service account management (session-gated inside each handler).
		g.GET("/api/account", a.AccountInfo)
		g.POST("/api/account/password", a.AccountSetPassword)
		g.DELETE("/api/passkeys/:id", a.PasskeyRemove)
	}
}

// Login starts the Authorization Code + PKCE flow: stash state/nonce/verifier/next in
// a short-lived signed cookie and redirect to the IdP.
func (a *Authenticator) Login(c *gin.Context) {
	if !a.Enabled() {
		c.Redirect(http.StatusFound, "/")
		return
	}
	state := randToken()
	nonce := randToken()
	verifier := oauth2.GenerateVerifier()

	flow, err := mintFlow(a.cfg.SessionSecret, flowClaims{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		Next:     sanitizeNext(c.Query("next")),
	}, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login init failed"})
		return
	}
	a.setCookie(c, flowCookie, flow, int(flowTTL/time.Second))

	url := a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	c.Redirect(http.StatusFound, url)
}

// Callback completes the flow: validate state, exchange the code, verify the ID
// token, enforce group access, then set the session cookie.
func (a *Authenticator) Callback(c *gin.Context) {
	if !a.Enabled() {
		c.Redirect(http.StatusFound, "/")
		return
	}
	ctx := c.Request.Context()

	flowTok, _ := c.Cookie(flowCookie)
	fc, err := parseFlow(a.cfg.SessionSecret, flowTok)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "login session expired — try again"})
		return
	}
	a.clearCookie(c, flowCookie)

	if errMsg := c.Query("error"); errMsg != "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "identity provider: " + errMsg})
		return
	}
	if !ctEqual(c.Query("state"), fc.State) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "state mismatch"})
		return
	}

	oauthToken, err := a.oauth.Exchange(ctx, c.Query("code"), oauth2.VerifierOption(fc.Verifier))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "token exchange failed"})
		return
	}
	rawID, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		c.JSON(http.StatusBadGateway, gin.H{"error": "no id_token in response"})
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "id_token verification failed"})
		return
	}
	if !ctEqual(idToken.Nonce, fc.Nonce) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "nonce mismatch"})
		return
	}

	var claims struct {
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	_ = idToken.Claims(&claims)

	if !a.groupAllowed(claims.Groups) {
		c.JSON(http.StatusForbidden, gin.H{"error": "your account is not in an allowed group"})
		return
	}

	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}

	// Optional post-login hook (multi-tenant provisioning / fine-grained allow).
	var role string
	if a.authorizer != nil {
		role, err = a.authorizer.Authorize(ctx, Identity{
			Subject: idToken.Subject, Email: claims.Email, Name: name, Groups: claims.Groups,
		})
		if err != nil {
			if errors.Is(err, ErrAccessDenied) {
				c.JSON(http.StatusForbidden, gin.H{"error": "your account is not authorized"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			}
			return
		}
	}

	session, err := mintSession(a.cfg.SessionSecret, idToken.Subject, claims.Email, name, role, rawID, claims.Groups, time.Now(), sessionTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session creation failed"})
		return
	}
	a.setCookie(c, sessionCookie, session, int(sessionTTL/time.Second))
	c.Redirect(http.StatusFound, fc.Next)
}

// Logout clears the session and, if the IdP advertises one, redirects to its
// RP-initiated logout endpoint.
func (a *Authenticator) Logout(c *gin.Context) {
	// Read the id_token (logout hint) before clearing the session cookie.
	var idHint string
	if tok, _ := c.Cookie(sessionCookie); tok != "" {
		if sc, err := parseSession(a.cfg.SessionSecret, tok); err == nil {
			idHint = sc.IDToken
		}
	}
	a.clearCookie(c, sessionCookie)
	a.clearCookie(c, csrfCookie)
	// Only do RP-initiated (IdP) logout when THIS session actually came from OIDC — i.e. it
	// carries an id_token. In-app sessions (password / passkey / email) must not bounce
	// through the IdP; they just return to our own login.
	if idHint != "" && a.Enabled() && a.endSession != "" {
		q := url.Values{
			"post_logout_redirect_uri": {a.postLogoutURL()},
			"client_id":                {a.cfg.ClientID},
			"id_token_hint":            {idHint},
		}
		c.Redirect(http.StatusFound, a.endSession+"?"+q.Encode())
		return
	}
	if a.LocalEnabled() {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	c.Redirect(http.StatusFound, "/welcome")
}

// postLogoutURL is the absolute URL the IdP returns the user to after logout — our public
// /welcome landing — derived from the configured redirect URL's origin. It must be
// registered on the OIDC client's logout_callback_urls for the IdP to honor it.
func (a *Authenticator) postLogoutURL() string {
	if u, err := url.Parse(a.cfg.RedirectURL); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/welcome"
	}
	return "/welcome"
}

// Me reports auth status + the current identity for the SPA. Always 200.
func (a *Authenticator) Me(c *gin.Context) {
	if !a.Enabled() {
		c.JSON(http.StatusOK, gin.H{"authEnabled": false, "authenticated": false})
		return
	}
	// The /auth group is public, so parse the cookie directly here.
	tok, _ := c.Cookie(sessionCookie)
	sc, err := parseSession(a.cfg.SessionSecret, tok)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"authEnabled": true, "authenticated": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"authEnabled":   true,
		"authenticated": true,
		"sub":           sc.Subject,
		"email":         sc.Email,
		"name":          sc.Name,
		"groups":        sc.Groups,
		"role":          sc.Role,
	})
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sanitizeNext keeps the post-login redirect to a local path (prevents open-redirect
// to an attacker host); defaults to the dashboard root.
func sanitizeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}
