package authx

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthConfig (GET /auth/config) is public and tells the SPA which sign-in methods are
// available, so the login UI renders only what's wired this phase.
func (a *Authenticator) AuthConfig(c *reqCtx) {
	emailOn := a.LocalEnabled() && a.email != nil && a.email.Configured()
	c.JSON(http.StatusOK, H{
		"local":      a.LocalEnabled(),
		"oidc":       a.Enabled(),
		"orgs":       a.OrgsEnabled(),
		"signupOpen": a.LocalEnabled(),
		"methods": H{
			"password":  a.LocalEnabled(),
			"email":     emailOn,
			"emailOtp":  emailOn,
			"passkey":   a.LocalEnabled() && a.wauthn != nil,
			"google":    a.socialConfigured("google"),
			"github":    a.socialConfigured("github"),
			"facebook":  a.socialConfigured("facebook"),
			"apple":     a.socialConfigured("apple"),
			"microsoft": a.socialConfigured("microsoft"),
			"discord":   a.socialConfigured("discord"),
		},
		// Every enabled social provider by slug (built-ins + generic OIDC), for rendering buttons.
		"socialProviders": a.enabledSocialProviders(),
		// The cookie whose value the SPA echoes in X-CSRF-Token (its name depends on Config.HostCookies).
		"csrfCookie": a.CSRFCookieName(),
	})
}

// sendVerifyEmail mints a verify-email token and emails the confirmation link (best-effort).
func (a *Authenticator) sendVerifyEmail(userID, email string) {
	raw, hash := newToken()
	if a.creds.CreateToken(purposeVerifyEmail, userID, email, hash, time.Now().Add(ttlVerifyEmail)) != nil {
		return
	}
	link := a.baseURL() + "/auth/email/verify?token=" + raw
	_ = a.sendAuthEmail(email, "Confirm your email", "Confirm your email",
		"Welcome! Confirm your email to activate your account and sign in.",
		"Confirm email", link, "This link is valid for 24 hours. If you didn't sign up, ignore this email.")
}

// Signup binding: the password a signup sets is chosen by whoever submitted the form, which needn't be
// the mailbox's owner. A short-lived signed cookie in the signing-up browser names the user and the
// password hash it set; the verify link keeps that password only when the browser presents a binding
// that still matches the stored hash.

const signupCookie = "sweep_signup"

type signupClaims struct {
	PasswordHash string `json:"ph"` // sha256 of the stored hash the signup set
	jwt.RegisteredClaims
}

func signupHashID(hash string) string {
	h := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(h[:])
}

func (a *Authenticator) setSignupBinding(c *reqCtx, userID, hash string) {
	now := time.Now()
	tok, err := signJWT(a.cfg.SessionSecret, signupClaims{PasswordHash: signupHashID(hash), RegisteredClaims: jwt.RegisteredClaims{
		Subject: userID, Audience: jwt.ClaimStrings{audSignup},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttlVerifyEmail)),
	}})
	if err == nil {
		a.setCookie(c, signupCookie, tok, int(ttlVerifyEmail/time.Second))
	}
}

// signupBound reports whether this browser signed up for userID with the password hash it holds now.
func (a *Authenticator) signupBound(c *reqCtx, userID, hash string) bool {
	var claims signupClaims
	if parseJWTMulti(a.verifySecrets(), a.cookieValue(c.Request, signupCookie), &claims, audSignup) != nil {
		return false
	}
	return claims.Subject == userID && subtle.ConstantTimeCompare([]byte(claims.PasswordHash), []byte(signupHashID(hash))) == 1
}

// claimMailbox records a mailbox proof for u (a redeemed link or code). When it is what verifies the
// address, a password already on the account was set by someone who hadn't proven the mailbox — a
// signup by anyone — so it is dropped, unless keepBoundPassword and this very browser set it
// (signupBound). The person who proved the mailbox is signed in and can set a password of their own.
// The drop and the verification are one step against a signup still in flight (setSignupPassword):
// its password lands before, and is dropped here, or not at all.
func (a *Authenticator) claimMailbox(c *reqCtx, u *AuthUser, keepBoundPassword bool) error {
	defer a.clearCookie(c, signupCookie)
	if u.EmailVerified {
		return nil
	}
	if ss, ok := a.creds.(SignupStore); ok {
		keep := ""
		if hash, _, err := a.passwordHash(u.ID); err == nil && keepBoundPassword && a.signupBound(c, u.ID, hash) {
			keep = hash
		}
		return ss.VerifyEmailKeepingPassword(u.ID, keep)
	}
	a.signupMu.Lock()
	defer a.signupMu.Unlock()
	if hash, _, err := a.passwordHash(u.ID); err == nil && !(keepBoundPassword && a.signupBound(c, u.ID, hash)) {
		if err := a.creds.SetPasswordHash(u.ID, "", ""); err != nil {
			return err
		}
	}
	return a.creds.SetEmailVerified(u.ID, true)
}

// setSignupPassword sets a signup's password on an account that is still unverified, and reports
// false — writing nothing — when the account has been verified since the signup read it: hashing
// takes long enough for the address's owner to prove the mailbox in between, and a password written
// after that would be an unproven one on a verified account.
func (a *Authenticator) setSignupPassword(userID, email, hash string) (bool, error) {
	if ss, ok := a.creds.(SignupStore); ok {
		return ss.SetPasswordHashIfUnverified(userID, hash, "bcrypt")
	}
	a.signupMu.Lock()
	defer a.signupMu.Unlock()
	if u, err := a.creds.UserByEmail(email); err != nil || u.ID != userID || u.EmailVerified {
		if err != nil && !errors.Is(err, ErrNoUser) {
			return false, err
		}
		return false, nil
	}
	return true, a.creds.SetPasswordHash(userID, hash, "bcrypt")
}

// EmailRequest (POST /auth/email/request) emails a one-time sign-in (magic) link. Always 200
// (anti-enumeration).
func (a *Authenticator) EmailRequest(c *reqCtx) {
	var body struct {
		Email, Next string
		Remember    bool
	}
	_ = c.ShouldBindJSON(&body)
	email := normEmail(body.Email)
	generic := H{"ok": true, "message": "If an account exists for that address, we've sent a sign-in link."}
	if !validEmail(email) || !a.ipLimiter.Allow("magic:"+c.rateIP()) || !a.acctLimiter.Allow("magic:"+email) {
		c.JSON(http.StatusOK, generic)
		return
	}
	// Look up + mint + send OFF the request path so the response time is identical whether or not an
	// account exists (the DB/token/SMTP work would otherwise be an account-enumeration timing oracle).
	remember := body.Remember
	next := sanitizeNext(body.Next)
	go func() {
		u, err := a.creds.UserByEmail(email)
		if err != nil {
			return
		}
		if blocked, _ := u.loginBlocked(); blocked {
			return
		}
		raw, hash := newToken()
		if a.creds.CreateToken(purposeMagicLogin, u.ID, email, hash, time.Now().Add(ttlMagicLogin)) != nil {
			return
		}
		link := a.baseURL() + "/auth/email/login?token=" + raw
		if next != "/" {
			link += "&next=" + url.QueryEscape(next)
		}
		if remember {
			link += "&remember=true"
		}
		_ = a.sendAuthEmail(email, "Your sign-in link", "Sign in",
			"Click below to sign in. This link is valid for 15 minutes and can be used once.",
			"Sign in", link, "If you didn't request this, you can ignore this email.")
	}()
	c.JSON(http.StatusOK, generic)
}

// EmailLogin (GET /auth/email/login?token=) redeems a magic-login token and signs the user
// in. Redeeming the emailed link proves email control, so it also confirms the address.
func (a *Authenticator) EmailLogin(c *reqCtx) { a.redeemAndLogin(c, purposeMagicLogin, true) }

// EmailVerify (GET /auth/email/verify?token=) redeems a verify-email token, marks the email
// verified, and signs the user in.
func (a *Authenticator) EmailVerify(c *reqCtx) { a.redeemAndLogin(c, purposeVerifyEmail, true) }

// redeemAndLogin consumes a single-use email token, optionally marks the email verified, then
// completes login and redirects. These are browser link-clicks (GET), so failures redirect to
// the login page with a message rather than returning JSON.
func (a *Authenticator) redeemAndLogin(c *reqCtx, purpose string, markVerified bool) {
	fail := func(msg string) {
		c.Redirect(http.StatusFound, a.baseURL()+"/login?error="+url.QueryEscape(msg))
	}
	token := c.Query("token")
	if token == "" {
		fail("missing token")
		return
	}
	claim, err := a.creds.ConsumeToken(purpose, hashToken(token))
	if err != nil {
		fail("this link is invalid or has expired")
		return
	}
	u, err := a.creds.UserByEmail(claim.Email)
	if err != nil {
		fail("account not found")
		return
	}
	// The link was mailed for one account. If that account has left the address and another holds
	// it now, the link is not theirs to be signed in by (as with a reset link).
	if claim.UserID != "" && u.ID != claim.UserID {
		fail("this link is invalid or has expired")
		return
	}
	if markVerified {
		if err := a.claimMailbox(c, u, purpose == purposeVerifyEmail); err != nil {
			fail("sign-in failed")
			return
		}
	}
	if blocked, msg := u.loginBlocked(); blocked {
		fail(msg)
		return
	}
	a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "magic", "login", true, purpose)
	tfr, err := a.completeLogin(c, Identity{Subject: u.Sub, Email: u.Email, Name: u.Name, EmailVerified: true, Local: true}, c.Query("remember") == "true", nil)
	if err != nil {
		fail("sign-in failed")
		return
	}
	if tfr {
		c.Redirect(http.StatusFound, withMFAMarker(sanitizeNext(c.Query("next"))))
		return
	}
	c.Redirect(http.StatusFound, sanitizeNext(c.Query("next")))
}
