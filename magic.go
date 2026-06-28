package authx

import (
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthConfig (GET /auth/config) is public and tells the SPA which sign-in methods are
// available, so the login UI renders only what's wired this phase.
func (a *Authenticator) AuthConfig(c *gin.Context) {
	emailOn := a.LocalEnabled() && a.email != nil && a.email.Configured()
	c.JSON(http.StatusOK, gin.H{
		"local":      a.LocalEnabled(),
		"oidc":       a.Enabled(),
		"signupOpen": a.LocalEnabled(),
		"methods": gin.H{
			"password": a.LocalEnabled(),
			"email":    emailOn,
			"passkey":  a.LocalEnabled() && a.wauthn != nil,
			"google":   a.socialConfigured("google"),
			"github":   a.socialConfigured("github"),
		},
	})
}

// sendVerifyEmail mints a verify-email token and emails the confirmation link (best-effort).
func (a *Authenticator) sendVerifyEmail(userID uint, email string) {
	raw, hash := newToken()
	if a.creds.CreateToken(purposeVerifyEmail, userID, email, hash, time.Now().Add(ttlVerifyEmail)) != nil {
		return
	}
	link := a.baseURL() + "/auth/email/verify?token=" + raw
	_ = a.sendAuthEmail(email, "Confirm your email", "Confirm your email",
		"Welcome! Confirm your email to activate your account and sign in.",
		"Confirm email", link, "This link is valid for 24 hours. If you didn't sign up, ignore this email.")
}

// EmailRequest (POST /auth/email/request) emails a one-time sign-in (magic) link. Always 200
// (anti-enumeration).
func (a *Authenticator) EmailRequest(c *gin.Context) {
	var body struct {
		Email, Next string
		Remember    bool
	}
	_ = c.ShouldBindJSON(&body)
	email := normEmail(body.Email)
	generic := gin.H{"ok": true, "message": "If an account exists for that address, we've sent a sign-in link."}
	if !validEmail(email) || !a.ipLimiter.allow("magic:"+c.ClientIP()) || !a.acctLimiter.allow("magic:"+email) {
		c.JSON(http.StatusOK, generic)
		return
	}
	if u, err := a.creds.UserByEmail(email); err == nil && !u.Disabled {
		raw, hash := newToken()
		if a.creds.CreateToken(purposeMagicLogin, u.ID, email, hash, time.Now().Add(ttlMagicLogin)) == nil {
			link := a.baseURL() + "/auth/email/login?token=" + raw
			if n := sanitizeNext(body.Next); n != "/" {
				link += "&next=" + url.QueryEscape(n)
			}
			if body.Remember {
				link += "&remember=true"
			}
			_ = a.sendAuthEmail(email, "Your sign-in link", "Sign in",
				"Click below to sign in. This link is valid for 15 minutes and can be used once.",
				"Sign in", link, "If you didn't request this, you can ignore this email.")
		}
	}
	c.JSON(http.StatusOK, generic)
}

// EmailLogin (GET /auth/email/login?token=) redeems a magic-login token and signs the user
// in. Redeeming the emailed link proves email control, so it also confirms the address.
func (a *Authenticator) EmailLogin(c *gin.Context) { a.redeemAndLogin(c, purposeMagicLogin, true) }

// EmailVerify (GET /auth/email/verify?token=) redeems a verify-email token, marks the email
// verified, and signs the user in.
func (a *Authenticator) EmailVerify(c *gin.Context) { a.redeemAndLogin(c, purposeVerifyEmail, true) }

// redeemAndLogin consumes a single-use email token, optionally marks the email verified, then
// completes login and redirects. These are browser link-clicks (GET), so failures redirect to
// the login page with a message rather than returning JSON.
func (a *Authenticator) redeemAndLogin(c *gin.Context, purpose string, markVerified bool) {
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
	if markVerified {
		_ = a.creds.SetEmailVerified(claim.UserID, true)
	}
	u, err := a.creds.UserByEmail(claim.Email)
	if err != nil {
		fail("account not found")
		return
	}
	if u.Disabled {
		fail("this account has been disabled")
		return
	}
	a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "magic", "login", true, purpose)
	if err := a.completeLogin(c, Identity{Subject: u.Sub, Email: u.Email, Name: u.Name}, c.Query("remember") == "true"); err != nil {
		fail("sign-in failed")
		return
	}
	c.Redirect(http.StatusFound, sanitizeNext(c.Query("next")))
}
