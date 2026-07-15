package authx

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Email OTP: a short numeric one-time code emailed for passwordless sign-in — an alternative to the
// magic LINK for clients where link-prefetch/rewriting (mail scanners) or native app UX make a typed
// code better. Like magic-link it only signs in an EXISTING user and proves the address on redemption.
const (
	ttlEmailOTP    = 10 * time.Minute
	maxOTPAttempts = 5 // guesses allowed before the code is invalidated (the load-bearing guard)
)

// otpHash is sha256(normalized-email + ":" + code) — salted by the email so a code is only ever valid
// for the address it was issued to (and a DB leak can't be matched across users).
func otpHash(email, code string) []byte {
	h := sha256.Sum256([]byte(normEmail(email) + ":" + strings.TrimSpace(code)))
	return h[:]
}

// newNumericCode returns a uniformly-random decimal code of the given length (no modulo bias).
func newNumericCode(digits int) (string, error) {
	max := big.NewInt(1)
	ten := big.NewInt(10)
	for i := 0; i < digits; i++ {
		max.Mul(max, ten)
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, n), nil
}

// EmailOTPSend (POST /auth/email-otp/send) emails a 6-digit sign-in code. Always 200 (anti-enumeration);
// the lookup + send happen off the request path so timing doesn't reveal whether the account exists.
func (a *Authenticator) EmailOTPSend(c *reqCtx) {
	var body struct{ Email string }
	_ = c.ShouldBindJSON(&body)
	email := normEmail(body.Email)
	generic := H{"ok": true, "message": "If an account exists for that address, we've sent a sign-in code."}
	if !validEmail(email) || a.email == nil || !a.email.Configured() ||
		!a.ipLimiter.Allow("emailotp:"+c.rateIP()) || !a.acctLimiter.Allow("emailotp:"+email) {
		c.JSON(http.StatusOK, generic)
		return
	}
	go func() {
		u, err := a.creds.UserByEmail(email)
		if err != nil {
			return
		}
		if blocked, _ := u.loginBlocked(); blocked {
			return
		}
		code, gerr := newNumericCode(6)
		if gerr != nil {
			return
		}
		if a.creds.CreateEmailOTP(purposeEmailOTP, email, otpHash(email, code), time.Now().Add(ttlEmailOTP), maxOTPAttempts) != nil {
			return
		}
		_ = a.sendAuthEmail(email, "Your sign-in code", "Your sign-in code",
			"Your one-time sign-in code is "+code+". It's valid for 10 minutes and can be used once.",
			"Go to sign-in", a.baseURL()+"/login",
			"If you didn't request this, you can ignore this email.")
	}()
	c.JSON(http.StatusOK, generic)
}

// EmailOTPVerify (POST /auth/email-otp/verify) checks a code and, on success, signs the user in through
// the shared completeLogin funnel. The store enforces the per-code attempt cap; we add the per-IP guard.
func (a *Authenticator) EmailOTPVerify(c *reqCtx) {
	var body struct {
		Email, Code, Next string
		Remember          bool
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	email := normEmail(body.Email)
	if a.ipLimiter != nil && !a.ipLimiter.Allow("emailotp:"+c.rateIP()) {
		c.tooMany("too many attempts — wait and try again")
		return
	}
	if !validEmail(email) || strings.TrimSpace(body.Code) == "" {
		c.JSON(http.StatusBadRequest, H{"error": "enter the code we emailed you"})
		return
	}
	claim, err := a.creds.VerifyEmailOTP(purposeEmailOTP, email, otpHash(email, body.Code))
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "that code is invalid or has expired"})
		return
	}
	u, err := a.creds.UserByEmail(claim.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "sign-in failed"})
		return
	}
	if blocked, msg := u.loginBlocked(); blocked {
		c.JSON(http.StatusForbidden, H{"error": msg})
		return
	}
	_ = a.creds.SetEmailVerified(u.ID, true) // redeeming an emailed code proves email control
	a.creds.RecordAudit(u.ID, u.Email, c.ClientIP(), "email_otp", "login", true, "")
	tfr, err := a.completeLogin(c, Identity{Subject: u.Sub, Email: u.Email, Name: u.Name, EmailVerified: true}, body.Remember, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "sign-in failed"})
		return
	}
	if tfr {
		c.JSON(http.StatusOK, H{"twoFactorRequired": true})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true, "next": sanitizeNext(body.Next)})
}
