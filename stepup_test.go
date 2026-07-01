package authx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestStepUpFresh(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a := &Authenticator{cfg: Config{SessionSecret: secret}}
	sess, _ := mintSession(secret, "local:u1", "u@x.com", "U", "", "", nil, time.Now(), sessionTTL)

	mintStep := func(sub string, iat time.Time) string {
		tok, _ := signJWT(secret, stepUpClaims{jwt.RegisteredClaims{
			Subject: sub, Audience: jwt.ClaimStrings{audStepUp},
			IssuedAt: jwt.NewNumericDate(iat), ExpiresAt: jwt.NewNumericDate(iat.Add(stepUpCookieTTL)),
		}})
		return tok
	}
	reqWith := func(cookies ...*http.Cookie) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		return r
	}
	sessCk := &http.Cookie{Name: sessionCookie, Value: sess}

	// No step-up cookie → not fresh.
	if a.StepUpFresh(reqWith(sessCk), 5*time.Minute) {
		t.Fatal("no step-up cookie → must not be fresh")
	}
	// A fresh step-up for the session user → fresh.
	fresh := reqWith(sessCk, &http.Cookie{Name: stepUpCookie, Value: mintStep("local:u1", time.Now())})
	if !a.StepUpFresh(fresh, 5*time.Minute) {
		t.Fatal("a fresh step-up for the session user should be fresh")
	}
	// maxAge=0 → stale.
	if a.StepUpFresh(fresh, 0) {
		t.Fatal("maxAge 0 → must not be fresh")
	}
	// An old step-up → stale.
	old := reqWith(sessCk, &http.Cookie{Name: stepUpCookie, Value: mintStep("local:u1", time.Now().Add(-20*time.Minute))})
	if a.StepUpFresh(old, 5*time.Minute) {
		t.Fatal("a 20-min-old step-up must be stale for a 5-min window")
	}
	// A step-up bound to a DIFFERENT subject must not elevate this session.
	crossed := reqWith(sessCk, &http.Cookie{Name: stepUpCookie, Value: mintStep("local:attacker", time.Now())})
	if a.StepUpFresh(crossed, 5*time.Minute) {
		t.Fatal("a step-up for another subject must not elevate this session")
	}
	// A step-up token must not parse as a session (audience segregation).
	if _, err := parseSession(secret, mintStep("local:u1", time.Now())); err == nil {
		t.Fatal("a step-up token must not be accepted as a session")
	}
}
