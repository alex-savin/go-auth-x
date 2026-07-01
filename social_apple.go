package authx

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Sign in with Apple. Apple is an OIDC provider, but the OAuth "client secret" is not static — it's
// a short-lived ES256 JWT the library signs from your .p8 key (RFC 7523), regenerated per token
// exchange. Apple also delivers its callback via form_post (a cross-site POST), so the login flow
// cookie is set SameSite=None (see setFlowCookieCrossSite) and the callback is read from the form.

const appleIssuer = "https://appleid.apple.com"

func (a *Authenticator) appleConfigured() bool {
	return a.cfg.AppleClientID != "" && a.cfg.AppleTeamID != "" && a.cfg.AppleKeyID != "" && a.cfg.ApplePrivateKey != ""
}

// enableApple parses the .p8 key and discovers Apple's OIDC endpoints. Best-effort: Apple stays off
// if the key can't be parsed or discovery fails.
func (a *Authenticator) enableApple(ctx context.Context) {
	if !a.appleConfigured() {
		return
	}
	key, err := parseApplePrivateKey(a.cfg.ApplePrivateKey)
	if err != nil {
		return
	}
	p, err := oidc.NewProvider(ctx, appleIssuer)
	if err != nil {
		return
	}
	a.appleKey = key
	a.appleVerifier = p.Verifier(&oidc.Config{ClientID: a.cfg.AppleClientID})
	a.appleOAuth = &oauth2.Config{
		ClientID: a.cfg.AppleClientID, // ClientSecret is generated per exchange (a signed JWT)
		Endpoint: p.Endpoint(), RedirectURL: a.socialRedirect("apple"),
		Scopes: []string{oidc.ScopeOpenID, "email"},
	}
}

func parseApplePrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	pemStr = strings.ReplaceAll(pemStr, "\\n", "\n") // tolerate \n-escaped env vars
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("apple: invalid PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apple: private key is not an EC key")
	}
	return ec, nil
}

// appleClientSecret signs the short-lived ES256 JWT Apple accepts as the OAuth client secret:
// iss=Team ID, sub=Services ID, aud=Apple, kid=Key ID.
func (a *Authenticator) appleClientSecret() (string, error) {
	if a.appleKey == nil {
		return "", errors.New("apple: no signing key")
	}
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    a.cfg.AppleTeamID,
		Subject:   a.cfg.AppleClientID,
		Audience:  jwt.ClaimStrings{appleIssuer},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
	})
	t.Header["kid"] = a.cfg.AppleKeyID
	return t.SignedString(a.appleKey)
}

// exchangeConfig returns the oauth2.Config to use for the token exchange. Apple needs a freshly
// signed client-secret JWT each time; every other provider uses its static config unchanged.
func (a *Authenticator) exchangeConfig(provider string, oc *oauth2.Config) (*oauth2.Config, error) {
	if provider != "apple" {
		return oc, nil
	}
	secret, err := a.appleClientSecret()
	if err != nil {
		return nil, err
	}
	cp := *oc
	cp.ClientSecret = secret
	return &cp, nil
}

// appleIdentity verifies Apple's id_token and returns the stable subject + verified email. The
// display name arrives only on the FIRST authorization, in the posted `user` field (not the token).
func (a *Authenticator) appleIdentity(ctx context.Context, tok *oauth2.Token, wantNonce, userJSON string) (subject, email, name string, err error) {
	if a.appleVerifier == nil {
		return "", "", "", errors.New("apple sign-in is not configured")
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", "", "", errors.New("no id_token in Apple's response")
	}
	idt, verr := a.appleVerifier.Verify(ctx, rawID)
	if verr != nil {
		return "", "", "", errors.New("apple id_token verification failed")
	}
	if !ctEqual(idt.Nonce, wantNonce) {
		return "", "", "", errors.New("nonce mismatch")
	}
	var cl struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"` // Apple sends a bool OR the string "true"
		AZP           string `json:"azp"`
	}
	_ = idt.Claims(&cl)
	if err := verifyAZP(idt.Audience, cl.AZP, a.cfg.AppleClientID); err != nil {
		return "", "", "", errors.New("id_token not authorized for this client")
	}
	verified := false
	switch t := cl.EmailVerified.(type) {
	case bool:
		verified = t
	case string:
		verified = t == "true"
	}
	if cl.Email == "" || !verified {
		return "", "", "", errors.New("your Apple ID email is not verified")
	}
	return idt.Subject, cl.Email, appleNameFromUser(userJSON), nil
}

// appleNameFromUser parses the first-authorization `user` field: {"name":{"firstName","lastName"}}.
func appleNameFromUser(userJSON string) string {
	if userJSON == "" {
		return ""
	}
	var u struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	if json.Unmarshal([]byte(userJSON), &u) != nil {
		return ""
	}
	return strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
}

// setFlowCookieCrossSite stores the login flow cookie with SameSite=None (+Secure) so it survives
// Apple's cross-site form_post callback. Secure is forced — Apple requires an HTTPS redirect.
func (a *Authenticator) setFlowCookieCrossSite(c *reqCtx, value string) {
	http.SetCookie(c.w, &http.Cookie{
		Name: flowCookie, Value: value, MaxAge: int(flowTTL / time.Second), Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode,
	})
}
