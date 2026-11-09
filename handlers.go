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
	"golang.org/x/oauth2"
)

// ctEqual is a constant-time string compare, used for the OAuth state and OIDC nonce checks so
// the callback doesn't leak a timing side-channel on these single-use anti-CSRF/replay values
// (OAuth 2.0 Security BCP / RFC 9700).
func ctEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// routes registers the /auth/* endpoints on a net/http ServeMux (Go 1.22 method+pattern routing).
// Used by Handler(). The consuming app owns its own login/landing UI; this only serves the JSON +
// ceremony endpoints. Disabled methods simply aren't registered.
func (a *Authenticator) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", a.wrap(a.Login))       // OIDC: start Authorization Code + PKCE
	mux.HandleFunc("GET /auth/callback", a.wrap(a.Callback)) // OIDC: redirect target
	mux.HandleFunc("GET /auth/logout", a.wrap(a.Logout))
	mux.HandleFunc("GET /auth/me", a.wrap(a.Me))
	mux.HandleFunc("GET /auth/config", a.wrap(a.AuthConfig)) // public: which methods are available
	// Session management + impersonation-exit act on the session cookie regardless of which methods are
	// enabled, so they're registered unconditionally (they self-gate and 501 when no session store).
	mux.HandleFunc("GET /auth/api/sessions", a.wrap(a.SessionList))
	mux.HandleFunc("DELETE /auth/api/sessions/{sid}", a.wrap(a.SessionRevoke))
	mux.HandleFunc("POST /auth/api/sessions/revoke-others", a.wrap(a.SessionRevokeOthers))
	mux.HandleFunc("POST /auth/api/stop-impersonating", a.wrap(a.StopImpersonating))
	if a.LocalEnabled() {
		mux.HandleFunc("POST /auth/password/signup", a.wrap(a.PasswordSignup))
		mux.HandleFunc("POST /auth/password/login", a.wrap(a.PasswordLogin))
		mux.HandleFunc("POST /auth/password/reset/request", a.wrap(a.PasswordResetRequest))
		mux.HandleFunc("POST /auth/password/reset/confirm", a.wrap(a.PasswordResetConfirm))
		mux.HandleFunc("POST /auth/email/request", a.wrap(a.EmailRequest))
		mux.HandleFunc("GET /auth/email/login", a.wrap(a.EmailLogin))
		mux.HandleFunc("GET /auth/email/verify", a.wrap(a.EmailVerify))
		mux.HandleFunc("POST /auth/email-otp/send", a.wrap(a.EmailOTPSend))     // numeric sign-in code
		mux.HandleFunc("POST /auth/email-otp/verify", a.wrap(a.EmailOTPVerify)) // redeem the code
		mux.HandleFunc("GET /auth/email/change", a.wrap(a.EmailChangeConfirm))  // confirm a new address
		mux.HandleFunc("POST /auth/webauthn/register/begin", a.wrap(a.WebauthnRegisterBegin))
		mux.HandleFunc("POST /auth/webauthn/register/finish", a.wrap(a.WebauthnRegisterFinish))
		mux.HandleFunc("POST /auth/webauthn/login/begin", a.wrap(a.WebauthnLoginBegin))
		mux.HandleFunc("POST /auth/webauthn/login/finish", a.wrap(a.WebauthnLoginFinish))
		mux.HandleFunc("GET /auth/api/account", a.wrap(a.AccountInfo))
		mux.HandleFunc("POST /auth/api/account/password", a.wrap(a.AccountSetPassword))
		mux.HandleFunc("POST /auth/api/account/email", a.wrap(a.AccountChangeEmailRequest)) // verified change-email
		mux.HandleFunc("DELETE /auth/api/account", a.wrap(a.AccountDelete))                 // self-service delete
		mux.HandleFunc("DELETE /auth/api/passkeys/{id}", a.wrap(a.PasskeyRemove))
		mux.HandleFunc("POST /auth/api/passkeys/{id}", a.wrap(a.PasskeyRename))
		mux.HandleFunc("DELETE /auth/api/identities/{provider}", a.wrap(a.OAuthUnlink)) // unlink social/OIDC
		mux.HandleFunc("POST /auth/reauth", a.wrap(a.ReAuth))                           // step-up re-auth for sensitive actions
	}
	if a.TwoFactorEnabled() {
		mux.HandleFunc("POST /auth/2fa/totp/begin", a.wrap(a.TOTPBegin))     // session-gated: start enrollment
		mux.HandleFunc("POST /auth/2fa/totp/confirm", a.wrap(a.TOTPConfirm)) // session-gated: confirm + recovery codes
		mux.HandleFunc("POST /auth/2fa/disable", a.wrap(a.TOTPDisable))      // session-gated
		mux.HandleFunc("POST /auth/2fa/verify", a.wrap(a.TwoFactorVerify))   // pending-cookie: finish a challenged login
		mux.HandleFunc("GET /auth/2fa/pending", a.wrap(a.TwoFactorPending))  // is a login awaiting a second factor?
		if a.wauthn != nil {                                                 // passkey as the second factor
			mux.HandleFunc("POST /auth/2fa/webauthn/begin", a.wrap(a.TwoFactorWebauthnBegin))
			mux.HandleFunc("POST /auth/2fa/webauthn/finish", a.wrap(a.TwoFactorWebauthnFinish))
		}
	}
	if a.anySocialConfigured() {
		mux.HandleFunc("GET /auth/social/{provider}/login", a.wrap(a.SocialLogin))
		mux.HandleFunc("GET /auth/social/{provider}/callback", a.wrap(a.SocialCallback))
		mux.HandleFunc("POST /auth/social/{provider}/callback", a.wrap(a.SocialCallback)) // Apple posts its callback (form_post)
	}
	if a.DirectoryEnabled() {
		a.adminRoutes(mux)
	}
	if a.OrgsEnabled() {
		mux.HandleFunc("GET /auth/orgs", a.wrap(a.OrgList))
		mux.HandleFunc("POST /auth/org/switch", a.wrap(a.OrgSwitch))
		mux.HandleFunc("GET /auth/org/members", a.wrap(a.OrgMemberList))
		mux.HandleFunc("POST /auth/org/members/{userId}", a.wrap(a.OrgMemberSetRole))
		mux.HandleFunc("DELETE /auth/org/members/{userId}", a.wrap(a.OrgMemberRemove))
		mux.HandleFunc("POST /auth/org/invites", a.wrap(a.OrgInviteCreate))
		mux.HandleFunc("GET /auth/org/invites", a.wrap(a.OrgInviteList))
		mux.HandleFunc("DELETE /auth/org/invites/{id}", a.wrap(a.OrgInviteRevoke))
		mux.HandleFunc("GET /auth/org/invite/accept", a.wrap(a.OrgInviteAccept))
		a.adminOrgRoutes(mux)
	}
}

// Login starts the Authorization Code + PKCE flow: stash state/nonce/verifier/next in
// a short-lived signed cookie and redirect to the IdP.
func (a *Authenticator) Login(c *reqCtx) {
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
		c.JSON(http.StatusInternalServerError, H{"error": "login init failed"})
		return
	}
	a.setCookie(c, flowCookie, flow, int(flowTTL/time.Second))

	url := a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	c.Redirect(http.StatusFound, url)
}

// Callback completes the flow: validate state, exchange the code, verify the ID
// token, enforce group access, then set the session cookie.
func (a *Authenticator) Callback(c *reqCtx) {
	if !a.Enabled() {
		c.Redirect(http.StatusFound, "/")
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

	if errMsg := c.Query("error"); errMsg != "" {
		c.JSON(http.StatusUnauthorized, H{"error": "identity provider: " + errMsg})
		return
	}
	if !ctEqual(c.Query("state"), fc.State) {
		c.JSON(http.StatusBadRequest, H{"error": "state mismatch"})
		return
	}

	oauthToken, err := a.oauth.Exchange(ctx, c.Query("code"), oauth2.VerifierOption(fc.Verifier))
	if err != nil {
		c.JSON(http.StatusBadGateway, H{"error": "token exchange failed"})
		return
	}
	rawID, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		c.JSON(http.StatusBadGateway, H{"error": "no id_token in response"})
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "id_token verification failed"})
		return
	}
	if !ctEqual(idToken.Nonce, fc.Nonce) {
		c.JSON(http.StatusUnauthorized, H{"error": "nonce mismatch"})
		return
	}

	var claims struct {
		Email             string   `json:"email"`
		EmailVerified     *bool    `json:"email_verified"` // pointer: distinguish absent from false
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
		AZP               string   `json:"azp"`
	}
	_ = idToken.Claims(&claims)
	if err := verifyAZP(idToken.Audience, claims.AZP, a.cfg.ClientID); err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "id_token not authorized for this client"})
		return
	}

	// Trust the token's email only when the issuer proved it (email_verified), or OIDC_ASSUME_VERIFIED
	// is set for a single trusted issuer AND the claim is absent — an explicit email_verified:false is
	// always honored. Without this an IdP that permits unverified email claims could hand an attacker a
	// session under a victim's address (matches the social login gate). No email is never verified.
	verified := claims.EmailVerified != nil && *claims.EmailVerified ||
		claims.EmailVerified == nil && a.cfg.OIDCAssumeVerified
	verified = verified && claims.Email != ""
	if claims.Email != "" && !verified {
		c.JSON(http.StatusUnauthorized, H{"error": "your email is not verified with this provider"})
		return
	}

	// The IdP's subject keys the account directly, so it must not name one of the library's own
	// subject namespaces ("scim:alice" would be the SCIM-provisioned Alice).
	if reservedSubject(idToken.Subject) {
		c.JSON(http.StatusUnauthorized, H{"error": "this identity can't sign in here"})
		return
	}

	if !a.groupAllowed(claims.Groups) {
		c.JSON(http.StatusForbidden, H{"error": "your account is not in an allowed group"})
		return
	}

	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}

	// The same funnel as every other method: the Authorizer (provisioning / fine-grained allow), the
	// disabled/banned refusal, the user's second factor, and session recording.
	tfr, err := a.completeLoginWith(c, Identity{
		Subject: idToken.Subject, Email: claims.Email, Name: name, Groups: claims.Groups, EmailVerified: verified,
	}, false, nil, rawID)
	var blocked loginBlockedError
	switch {
	case errors.Is(err, ErrAccessDenied):
		c.JSON(http.StatusForbidden, H{"error": "your account is not authorized"})
		return
	case errors.As(err, &blocked):
		c.JSON(http.StatusForbidden, H{"error": blocked.msg})
		return
	case err != nil:
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	if tfr {
		c.Redirect(http.StatusFound, withMFAMarker(fc.Next))
		return
	}
	c.Redirect(http.StatusFound, fc.Next)
}

// reservedSubject reports whether an IdP subject falls in a namespace the library mints subjects in
// (local accounts, bootstrap placeholders, SCIM and LDAP provisioning, social identities).
func reservedSubject(sub string) bool {
	for _, p := range []string{"local:", "bootstrap:", "scim:", "ldap:", "social:"} {
		if strings.HasPrefix(strings.ToLower(sub), p) {
			return true
		}
	}
	return false
}

// Logout clears the session and, if the IdP advertises one, redirects to its
// RP-initiated logout endpoint.
func (a *Authenticator) Logout(c *reqCtx) {
	// Read the id_token (logout hint) + session id before clearing the session cookie.
	var idHint, sid string
	if tok, _ := c.Cookie(sessionCookie); tok != "" {
		if sc, err := parseSessionMulti(a.verifySecrets(), tok); err == nil {
			idHint = sc.IDToken
			sid = sc.SID
		}
	}
	// If server-side session tracking is on, revoke this session's record too (belt-and-suspenders
	// with clearing the cookie — so a copy of the cookie can't be replayed after logout).
	if sid != "" && a.sessions != nil {
		_ = a.sessions.RevokeSession(sid)
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
// authEnabled follows enforcing() — true when ANY auth method gates requests (OIDC OR in-app
// local auth) — so a password/passkey-only deployment still reports signed-in state.
func (a *Authenticator) Me(c *reqCtx) {
	if !a.enforcing() {
		c.JSON(http.StatusOK, H{"authEnabled": false, "authenticated": false})
		return
	}
	// The /auth group is public, so parse the cookie directly here.
	tok, _ := c.Cookie(sessionCookie)
	sc, err := parseSessionMulti(a.verifySecrets(), tok)
	if err != nil || a.sessionRevoked(sc) {
		c.JSON(http.StatusOK, H{"authEnabled": true, "authenticated": false})
		return
	}
	resp := H{
		"authEnabled":    true,
		"authenticated":  true,
		"sub":            sc.Subject,
		"email":          sc.Email,
		"name":           sc.Name,
		"groups":         sc.Groups,
		"role":           sc.Role,
		"impersonatedBy": sc.ImpersonatedBy,
	}
	// Org surface for the SPA: the active org (details + LIVE role) and every membership, so one
	// bootstrap call renders both the current workspace and the org picker. On a STORE failure the
	// org keys are OMITTED entirely (Me stays always-200) — absence means "unknown, retry", which
	// the SPA can tell apart from the empty values a genuine zero-membership user gets.
	if a.OrgsEnabled() {
		if org, orgRole, orgs, err := a.meOrgs(sc); err == nil {
			resp["org"], resp["orgRole"], resp["orgs"] = org, orgRole, orgs
		}
	}
	c.JSON(http.StatusOK, resp)
}

// meOrgs assembles /auth/me's org fields from the store (NOT just the cookie): org, the active
// org's view or nil; orgRole, the LIVE role in it ("" when the claim went stale — removed member,
// deleted org); orgs, the flattened membership list for the picker. A session subject with no
// credential-store row is a legitimate zero-membership answer, not an error.
func (a *Authenticator) meOrgs(sc *SessionClaims) (org any, orgRole string, orgs []H, err error) {
	u, uerr := a.creds.UserBySub(sc.Subject)
	if errors.Is(uerr, ErrNoUser) {
		return nil, "", []H{}, nil
	}
	if uerr != nil {
		return nil, "", nil, uerr
	}
	ms, merr := a.orgs.UserOrgs(u.ID)
	if merr != nil {
		return nil, "", nil, merr
	}
	orgs = userOrgViews(ms)
	for i := range ms {
		if sc.Org != "" && ms[i].Org.ID == sc.Org {
			org, orgRole = orgs[i], ms[i].Role
		}
	}
	return org, orgRole, orgs, nil
}

// verifyAZP enforces OIDC Core §3.1.3.7 items 4-5: a multi-audience id_token MUST carry azp, and when
// azp is present it MUST name this client — else the token was authorized for a different party.
func verifyAZP(aud []string, azp, clientID string) error {
	if len(aud) > 1 && azp == "" {
		return errors.New("id_token has multiple audiences but no azp")
	}
	if azp != "" && !ctEqual(azp, clientID) {
		return errors.New("id_token azp is not this client")
	}
	return nil
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is catastrophic; issuing a guessable state/CSRF/API-key token would be
		// worse than aborting. Fail closed (matches oauth2.GenerateVerifier's contract).
		panic("authx: crypto/rand read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sanitizeNext keeps the post-login redirect to a local path (prevents open-redirect to an attacker
// host); defaults to the dashboard root. It rejects scheme-relative targets ("//evil.com" AND
// "/\evil.com" — browsers treat a backslash as a slash) and any target containing a control byte:
// browsers strip ASCII whitespace such as a tab before parsing a URL, so "/\t/evil.com" would be read
// as "//evil.com" (scheme-relative) and redirect off-site.
func sanitizeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") {
		return "/"
	}
	for i := 0; i < len(next); i++ {
		if next[i] < 0x20 || next[i] == 0x7f { // control byte (tab/newline/…) → reject
			return "/"
		}
	}
	if len(next) > 1 && (next[1] == '/' || next[1] == '\\') {
		return "/"
	}
	return next
}
