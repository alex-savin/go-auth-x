package authx

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// dummyHash burns ~the same time as a real compare when the account/credential is absent,
// so response timing doesn't leak whether an email is registered.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer-not-a-real-password"), bcryptCost)

// a tiny embedded set of the most-common breached passwords (NIST 800-63B: block the worst,
// don't impose composition rules).
var commonPasswords = map[string]bool{
	"password": true, "password1": true, "12345678": true, "123456789": true, "1234567890": true,
	"qwertyuiop": true, "qwerty123": true, "111111111": true, "iloveyou": true, "admin123": true,
	"welcome1": true, "letmein1": true, "password123": true, "changeme": true, "trustno1": true,
}

// passwordStrengthError returns a user-facing reason a password is unacceptable, or "".
func passwordStrengthError(pw, email string) string {
	if len(pw) < 10 {
		return "password must be at least 10 characters"
	}
	if len(pw) > 200 {
		return "password is too long"
	}
	lower := strings.ToLower(pw)
	if commonPasswords[lower] {
		return "that password is too common — choose another"
	}
	// Only flag the email local-part when it's long enough to be meaningful — a 1-2 char
	// local-part would match almost any password.
	if local := emailLocalPart(email); len(local) >= 4 && strings.Contains(lower, strings.ToLower(local)) {
		return "password must not contain your email address"
	}
	return ""
}

func emailLocalPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

func hashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(b), err
}

// PasswordSignup (POST /auth/password/signup) creates a local, unverified account and emails
// a verification link. Always responds 200 with a generic message (anti-enumeration); it
// never overwrites the password of an existing VERIFIED account.
func (a *Authenticator) PasswordSignup(c *reqCtx) {
	var body struct{ Email, Password, Name string }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	email := normEmail(body.Email)
	if !validEmail(email) {
		c.JSON(http.StatusBadRequest, H{"error": "enter a valid email address"})
		return
	}
	if msg := passwordStrengthError(body.Password, email); msg != "" {
		c.JSON(http.StatusBadRequest, H{"error": msg})
		return
	}
	if !a.ipLimiter.Allow("signup:" + c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, H{"error": "too many attempts — try again shortly"})
		return
	}
	const generic = "Check your email to finish creating your account."

	u, err := a.creds.UserByEmail(email)
	switch {
	case errors.Is(err, ErrNoUser):
		nu, cerr := a.creds.CreateLocalUser(email, strings.TrimSpace(body.Name))
		if cerr != nil {
			c.JSON(http.StatusInternalServerError, H{"error": "could not create account"})
			return
		}
		u = nu
	case err != nil:
		c.JSON(http.StatusInternalServerError, H{"error": "could not create account"})
		return
	case u.EmailVerified:
		// Account already exists and is verified: do NOT touch its password. Nudge them to
		// sign in / reset instead, and still answer generically.
		base := a.baseURL()
		_ = a.sendAuthEmail(email, "You already have an account",
			"You already have an account",
			"Someone tried to sign up with this email. If it was you, just sign in — or reset your password if you've forgotten it.",
			"Sign in", base+"/login",
			"If you didn't try to sign up, you can ignore this email.")
		a.creds.RecordAudit(u.ID, email, c.ClientIP(), "password", "signup_existing", false, "")
		c.JSON(http.StatusOK, H{"ok": true, "message": generic})
		return
	}

	// New or still-unverified account: (re)set the password and send a fresh verify link.
	hash, herr := hashPassword(body.Password)
	if herr != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not create account"})
		return
	}
	if err := a.creds.SetPasswordHash(u.ID, hash, "bcrypt"); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not create account"})
		return
	}
	a.sendVerifyEmail(u.ID, email)
	a.creds.RecordAudit(u.ID, email, c.ClientIP(), "password", "signup", true, "")
	c.JSON(http.StatusOK, H{"ok": true, "message": generic})
}

// PasswordLogin (POST /auth/password/login) verifies email+password and starts a session.
func (a *Authenticator) PasswordLogin(c *reqCtx) {
	var body struct {
		Email, Password, Next string
		Remember              bool
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	email := normEmail(body.Email)
	ip := c.ClientIP()
	if !a.ipLimiter.Allow("login:" + ip) {
		c.JSON(http.StatusTooManyRequests, H{"error": "too many attempts — try again shortly"})
		return
	}
	// Per-account soft lockout from durable failure history (owner exempt). Recovery via the
	// email-link / reset paths stays open regardless.
	if !a.isOwnerEmail(email) {
		if fails, _ := a.creds.RecentFailures(email, time.Now().Add(-15*time.Minute)); fails >= 5 {
			c.JSON(http.StatusTooManyRequests, H{"error": "too many attempts — use “email me a sign-in link” instead"})
			return
		}
	}

	invalid := func() {
		c.JSON(http.StatusUnauthorized, H{"error": "incorrect email or password"})
	}
	u, err := a.creds.UserByEmail(email)
	if errors.Is(err, ErrNoUser) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(body.Password))
		a.creds.RecordAudit(0, email, ip, "password", "login", false, "no_user")
		invalid()
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "login failed"})
		return
	}
	hash, _, perr := a.creds.PasswordHash(u.ID)
	if errors.Is(perr, ErrNoCredential) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(body.Password))
		a.creds.RecordAudit(u.ID, email, ip, "password", "login", false, "no_password")
		invalid()
		return
	}
	if perr != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "login failed"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil {
		a.creds.RecordAudit(u.ID, email, ip, "password", "login", false, "bad_password")
		invalid()
		return
	}
	if u.Disabled {
		c.JSON(http.StatusForbidden, H{"error": "this account has been disabled"})
		return
	}
	if !u.EmailVerified {
		// Correct password but unverified: (re)send the confirmation link so "check your
		// inbox" is truthful. Rate-limited per account to avoid spamming.
		if a.acctLimiter.Allow("verify:" + email) {
			a.sendVerifyEmail(u.ID, email)
		}
		c.JSON(http.StatusForbidden, H{"error": "Please confirm your email — we've sent a fresh confirmation link to your inbox.", "needsVerify": true})
		return
	}
	a.creds.RecordAudit(u.ID, email, ip, "password", "login", true, "")
	if err := a.completeLogin(c, Identity{Subject: u.Sub, Email: u.Email, Name: u.Name, EmailVerified: true}, body.Remember); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "login failed"})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true, "next": sanitizeNext(body.Next)})
}

// PasswordResetRequest (POST /auth/password/reset/request) emails a reset link. Always 200.
func (a *Authenticator) PasswordResetRequest(c *reqCtx) {
	var body struct{ Email string }
	_ = c.ShouldBindJSON(&body)
	email := normEmail(body.Email)
	generic := H{"ok": true, "message": "If an account exists for that address, we've sent a reset link."}
	if !validEmail(email) || !a.ipLimiter.Allow("reset:"+c.ClientIP()) || !a.acctLimiter.Allow("reset:"+email) {
		c.JSON(http.StatusOK, generic)
		return
	}
	if u, err := a.creds.UserByEmail(email); err == nil && !u.Disabled {
		raw, hash := newToken()
		if a.creds.CreateToken(purposePasswordReset, u.ID, email, hash, time.Now().Add(ttlPasswordReset)) == nil {
			link := a.baseURL() + "/reset?token=" + raw
			_ = a.sendAuthEmail(email, "Reset your password", "Reset your password",
				"Click below to choose a new password. This link is valid for 1 hour and can be used once.",
				"Reset password", link, "If you didn't request this, you can ignore this email.")
		}
	}
	c.JSON(http.StatusOK, generic)
}

// PasswordResetConfirm (POST /auth/password/reset/confirm) redeems a reset token and sets a
// new password. The token proves email control, so we also mark the email verified.
func (a *Authenticator) PasswordResetConfirm(c *reqCtx) {
	var body struct{ Token, Password string }
	if err := c.ShouldBindJSON(&body); err != nil || body.Token == "" {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	claim, err := a.creds.ConsumeToken(purposePasswordReset, hashToken(body.Token))
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "this reset link is invalid or has expired"})
		return
	}
	if msg := passwordStrengthError(body.Password, claim.Email); msg != "" {
		c.JSON(http.StatusBadRequest, H{"error": msg})
		return
	}
	hash, herr := hashPassword(body.Password)
	if herr != nil || a.creds.SetPasswordHash(claim.UserID, hash, "bcrypt") != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not update password"})
		return
	}
	_ = a.creds.SetEmailVerified(claim.UserID, true)
	a.creds.RecordAudit(claim.UserID, claim.Email, c.ClientIP(), "password", "reset", true, "")
	c.JSON(http.StatusOK, H{"ok": true, "message": "Your password has been updated. You can now sign in."})
}

// isOwnerEmail reports whether the email is the configured instance owner (lockout-exempt).
func (a *Authenticator) isOwnerEmail(email string) bool {
	return a.cfg.OwnerEmail != "" && normEmail(email) == a.cfg.OwnerEmail
}
