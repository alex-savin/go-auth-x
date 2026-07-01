package authx

import (
	"strings"
	"testing"
	"time"
)

// TestHOTP_RFC4226 checks the HOTP core against the published RFC 4226 Appendix D test vectors
// (secret "12345678901234567890", counters 0..9).
func TestHOTP_RFC4226(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := hotp(secret, uint64(i)); got != w {
			t.Fatalf("hotp(counter=%d) = %s, want %s", i, got, w)
		}
	}
}

// TestTOTPValidate checks RFC 6238 (SHA1) validation, the skew window, and a self round-trip.
func TestTOTPValidate(t *testing.T) {
	secretB32 := b32.EncodeToString([]byte("12345678901234567890"))

	// RFC 6238: at T=59s, step = 59/30 = 1 → the 6-digit tail is HOTP(counter=1) = 287082.
	at := time.Unix(59, 0)
	if step, ok := totpValidate(secretB32, "287082", at); !ok || step != 1 {
		t.Fatalf("287082 @T=59 should validate at step 1: ok=%v step=%d", ok, step)
	}

	// Past-leaning skew: the PREVIOUS step validates (clock drift); a FUTURE step does not.
	prevStepCode := hotp([]byte("12345678901234567890"), 0)
	if _, ok := totpValidate(secretB32, prevStepCode, at); !ok {
		t.Fatal("a previous-step code should validate within the skew window")
	}
	if _, ok := totpValidate(secretB32, hotp([]byte("12345678901234567890"), 2), at); ok {
		t.Fatal("a future-step code must NOT validate (past-leaning window)")
	}

	// Wrong code, wrong length, junk secret all fail.
	if _, ok := totpValidate(secretB32, "000000", at); ok {
		t.Fatal("a wrong code must not validate")
	}
	if _, ok := totpValidate(secretB32, "12345", at); ok {
		t.Fatal("a wrong-length code must not validate")
	}
	if _, ok := totpValidate("!!!notbase32", "287082", at); ok {
		t.Fatal("an undecodable secret must not validate")
	}

	// Round-trip: a freshly generated secret validates its own current code.
	sec, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := b32.DecodeString(sec)
	now := time.Now()
	code := hotp(raw, uint64(now.Unix())/totpPeriod)
	if _, ok := totpValidate(sec, code, now); !ok {
		t.Fatal("a freshly generated secret should validate its own current code")
	}
}

func TestTOTPURI(t *testing.T) {
	uri := totpURI("ABCDEF", "go-auth-x", "alice@example.com")
	for _, want := range []string{"otpauth://totp/", "secret=ABCDEF", "issuer=go-auth-x", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("otpauth URI %q missing %q", uri, want)
		}
	}
}
