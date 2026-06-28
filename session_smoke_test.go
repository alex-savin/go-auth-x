package authx

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestSessionRoundTrip exercises the BFF session core: a minted session parses back to the same
// claims, and a tampered/foreign-key token is rejected (HS256 integrity).
func TestSessionRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	tok, err := mintSession(secret, "local:abc", "a@b.com", "Alice", "admin", "", []string{"g1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("mintSession: %v", err)
	}
	sc, err := parseSession(secret, tok)
	if err != nil {
		t.Fatalf("parseSession: %v", err)
	}
	if sc.Subject != "local:abc" || sc.Email != "a@b.com" || sc.Name != "Alice" {
		t.Fatalf("claims round-trip mismatch: %+v", sc)
	}
	if _, err := parseSession([]byte("wrong-secret-wrong-secret-wrong!"), tok); err == nil {
		t.Fatal("expected a token signed with a different secret to be rejected")
	}
}

// TestPasswordHashVerify confirms the bcrypt hash/verify helper round-trips.
func TestPasswordHashVerify(t *testing.T) {
	h, err := hashPassword("a-strong-enough-passphrase")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte("a-strong-enough-passphrase")) != nil {
		t.Fatal("hash did not verify against the correct password")
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte("wrong")) == nil {
		t.Fatal("hash verified a wrong password")
	}
}
