package authx

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
)

const wauthnFlowCookie = "sweep_wauthn_flow"

// enableWebauthn builds the WebAuthn relying-party instance from the app origin. rpID is the
// app host (e.g. trader.savin.nyc) — same-origin, so passkeys are enrolled and asserted in
// our own page with no IdP hand-off. Best-effort; passkeys stay off if it can't initialize.
func (a *Authenticator) enableWebauthn() {
	base := a.baseURL()
	if base == "" || a.wauthn != nil {
		return
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return
	}
	rpID := os.Getenv("WEBAUTHN_RPID")
	if rpID == "" {
		rpID = u.Hostname()
	}
	name := os.Getenv("WEBAUTHN_RP_NAME")
	if name == "" {
		name = a.brandName()
	}
	if w, err := webauthn.New(&webauthn.Config{
		RPID: rpID, RPDisplayName: name, RPOrigins: []string{base},
		// Require user verification (PIN/biometric) so a passkey is a real multi-factor credential,
		// not a bare possession factor — the library enforces the UV flag at Finish.
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired},
	}); err == nil {
		a.wauthn = w
	}
}

// --- webauthn.User adapter over our AuthUser + passkeys ---

type wauthnUser struct {
	handle      []byte
	email, name string
	creds       []webauthn.Credential
}

func (u *wauthnUser) WebAuthnID() []byte   { return u.handle }
func (u *wauthnUser) WebAuthnName() string { return u.email }
func (u *wauthnUser) WebAuthnDisplayName() string {
	if u.name != "" {
		return u.name
	}
	return u.email
}
func (u *wauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (a *Authenticator) wauthnUserFor(au *AuthUser) (*wauthnUser, error) {
	handle, err := a.creds.EnsureWebauthnHandle(au.ID)
	if err != nil {
		return nil, err
	}
	pks, err := a.creds.Passkeys(au.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(pks))
	for _, p := range pks {
		creds = append(creds, passkeyToCredential(p))
	}
	return &wauthnUser{handle: handle, email: au.Email, name: au.Name, creds: creds}, nil
}

func passkeyToCredential(p Passkey) webauthn.Credential {
	var tr []protocol.AuthenticatorTransport
	for _, t := range strings.Split(p.Transports, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tr = append(tr, protocol.AuthenticatorTransport(t))
		}
	}
	return webauthn.Credential{
		ID:              p.CredentialID,
		PublicKey:       p.PublicKey,
		AttestationType: p.AttestationType,
		Transport:       tr,
		Flags:           webauthn.CredentialFlags{BackupEligible: p.BackupEligible, BackupState: p.BackupState},
		Authenticator:   webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
	}
}

func credentialToPasskey(c *webauthn.Credential, name string) Passkey {
	var tr []string
	for _, t := range c.Transport {
		tr = append(tr, string(t))
	}
	return Passkey{
		CredentialID:    c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		AAGUID:          c.Authenticator.AAGUID,
		SignCount:       c.Authenticator.SignCount,
		Transports:      strings.Join(tr, ","),
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
		Name:            name,
	}
}

// --- challenge stored in a short-lived signed cookie (mirrors the OIDC flow cookie) ---

type webauthnFlowClaims struct {
	Session []byte `json:"s"`
	jwt.RegisteredClaims
}

func (a *Authenticator) setWauthnFlow(c *reqCtx, sd *webauthn.SessionData) error {
	raw, err := json.Marshal(sd)
	if err != nil {
		return err
	}
	tok, err := signJWT(a.cfg.SessionSecret, webauthnFlowClaims{
		Session:          raw,
		RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{audWebauthn}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute))},
	})
	if err != nil {
		return err
	}
	a.setCookie(c, wauthnFlowCookie, tok, 300)
	return nil
}

func (a *Authenticator) getWauthnFlow(c *reqCtx) (*webauthn.SessionData, error) {
	tok, _ := c.Cookie(wauthnFlowCookie)
	var claims webauthnFlowClaims
	if err := parseJWTMulti(a.verifySecrets(), tok, &claims, audWebauthn); err != nil {
		return nil, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(claims.Session, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

// currentAuthUser resolves the signed-in user from the session cookie (for session-gated
// self-service endpoints registered on the public /auth group).
func (a *Authenticator) currentAuthUser(c *reqCtx) (*AuthUser, error) {
	tok, _ := c.Cookie(sessionCookie)
	sc, err := parseSessionMulti(a.verifySecrets(), tok)
	if err != nil {
		return nil, err
	}
	if a.sessionRevoked(sc) {
		return nil, errors.New("session revoked")
	}
	return a.creds.UserBySub(sc.Subject)
}

// --- ceremonies ---

// WebauthnRegisterBegin (POST /auth/webauthn/register/begin) starts passkey enrolment for the
// signed-in user.
func (a *Authenticator) WebauthnRegisterBegin(c *reqCtx) {
	if a.wauthn == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "passkeys not available"})
		return
	}
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "sign in first"})
		return
	}
	wu, err := a.wauthnUserFor(au)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start enrolment"})
		return
	}
	var excl []protocol.CredentialDescriptor
	for _, cr := range wu.creds {
		excl = append(excl, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: cr.ID})
	}
	// Require a DISCOVERABLE (resident) credential and DO NOT pin AuthenticatorAttachment, so the
	// enrolled passkey is usable passwordless AND cross-device: leaving attachment unset lets the
	// browser offer both platform authenticators (Touch ID / Windows Hello) and cross-platform
	// ones — a phone over the FIDO2 hybrid transport (the QR-code flow) or a roaming security key.
	// Discoverable credentials are also what BeginDiscoverableLogin needs for QR sign-in to work.
	reqResidentKey := true
	sel := protocol.AuthenticatorSelection{
		ResidentKey:        protocol.ResidentKeyRequirementRequired,
		RequireResidentKey: &reqResidentKey,
		UserVerification:   protocol.VerificationRequired,
	}
	creation, sd, err := a.wauthn.BeginRegistration(wu, webauthn.WithExclusions(excl), webauthn.WithAuthenticatorSelection(sel))
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start enrolment"})
		return
	}
	if err := a.setWauthnFlow(c, sd); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start enrolment"})
		return
	}
	c.JSON(http.StatusOK, creation)
}

// WebauthnRegisterFinish (POST /auth/webauthn/register/finish?name=) stores the new passkey.
// The WebAuthn attestation is the request body; the optional label comes via ?name=.
func (a *Authenticator) WebauthnRegisterFinish(c *reqCtx) {
	if a.wauthn == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "passkeys not available"})
		return
	}
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "sign in first"})
		return
	}
	sd, err := a.getWauthnFlow(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "enrolment expired — try again"})
		return
	}
	a.clearCookie(c, wauthnFlowCookie)
	wu, err := a.wauthnUserFor(au)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not finish enrolment"})
		return
	}
	cred, err := a.wauthn.FinishRegistration(wu, *sd, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "passkey registration failed"})
		return
	}
	name := strings.TrimSpace(c.Query("name"))
	if name == "" {
		name = "Passkey"
	}
	if err := a.creds.AddPasskey(au.ID, credentialToPasskey(cred, name)); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not save passkey"})
		return
	}
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "passkey", "passkey_added", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}

// WebauthnLoginBegin (POST /auth/webauthn/login/begin) starts a discoverable passkey login.
// Discoverable (usernameless) login sends an EMPTY allowCredentials list, which is exactly what
// makes the browser offer "use a phone or tablet" — the FIDO2 hybrid transport that shows a QR
// code so the user can sign in with a passkey on another device. No server-side QR handling is
// needed; the platform negotiates it as long as we stay discoverable and the rpID is fixed.
func (a *Authenticator) WebauthnLoginBegin(c *reqCtx) {
	if a.wauthn == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "passkeys not available"})
		return
	}
	assertion, sd, err := a.wauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start sign-in"})
		return
	}
	if err := a.setWauthnFlow(c, sd); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not start sign-in"})
		return
	}
	c.JSON(http.StatusOK, assertion)
}

// WebauthnLoginFinish (POST /auth/webauthn/login/finish?next=) verifies the assertion and
// signs the user in. The assertion is the body; the redirect target comes via ?next=.
func (a *Authenticator) WebauthnLoginFinish(c *reqCtx) {
	if a.wauthn == nil {
		c.JSON(http.StatusNotImplemented, H{"error": "passkeys not available"})
		return
	}
	sd, err := a.getWauthnFlow(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "sign-in expired — try again"})
		return
	}
	a.clearCookie(c, wauthnFlowCookie)

	var matched *AuthUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, herr := a.creds.UserByWebauthnHandle(userHandle)
		if herr != nil {
			return nil, herr
		}
		matched = u
		wu, werr := a.wauthnUserFor(u)
		if werr != nil {
			return nil, werr
		}
		return wu, nil
	}
	cred, err := a.wauthn.FinishDiscoverableLogin(handler, *sd, c.Request)
	if err != nil || matched == nil {
		c.JSON(http.StatusUnauthorized, H{"error": "passkey sign-in failed"})
		return
	}
	if blocked, msg := matched.loginBlocked(); blocked {
		c.JSON(http.StatusForbidden, H{"error": msg})
		return
	}
	// Clone detection: the library flags CloneWarning when the authenticator's signature
	// counter went backwards/stalled vs what we stored — a sign the credential may have been
	// copied. Refuse the login and leave an audit trail rather than accept it silently.
	if cred.Authenticator.CloneWarning {
		a.creds.RecordAudit(matched.ID, matched.Email, c.ClientIP(), "passkey", "clone_warning", false, "")
		c.JSON(http.StatusUnauthorized, H{"error": "passkey sign-in failed (security check)"})
		return
	}
	_ = a.creds.TouchPasskey(cred.ID, cred.Authenticator.SignCount)
	a.creds.RecordAudit(matched.ID, matched.Email, c.ClientIP(), "passkey", "login", true, "")
	// Pass this passkey's credential ID as the first factor, so passkey-as-2FA can't be satisfied by the
	// very same credential.
	tfr, err := a.completeLogin(c, Identity{Subject: matched.Sub, Email: matched.Email, Name: matched.Name, EmailVerified: true}, c.Query("remember") == "true", cred.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	if tfr {
		c.JSON(http.StatusOK, H{"twoFactorRequired": true})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true, "next": sanitizeNext(c.Query("next")), "email": matched.Email})
}
