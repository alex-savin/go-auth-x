package authx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) over HOTP (RFC 4226), implemented with the standard library ONLY — no third-party
// dependency. (API shape inspired by github.com/Ja7ad/otp; the algorithm is ~60 lines and provable
// against the published RFC test vectors, so a security library is better off owning it.) Defaults
// match what authenticator apps expect: HMAC-SHA1, 6 digits, a 30-second period, and a past-leaning
// skew window (current + previous step) for clock drift. The library returns the otpauth:// URI + base32 secret and lets the
// frontend render the QR — no server-side image/barcode dependency.

const (
	totpDigits = 6
	totpPeriod = 30 // seconds
)

// base32 (RFC 4648, no padding, upper-case) is what authenticator apps read from the otpauth URI.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret returns a fresh base32 secret (160 bits, per RFC 4226 §4 requirement R6).
func newTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// hotp computes the RFC 4226 HOTP value for a counter (dynamic truncation → 6 digits).
func hotp(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// totpValidate reports whether code is valid for the base32 secret at time t, within a past-leaning
// skew window (current + previous step; see below). It returns the matched step so the caller can
// reject replays (a step already consumed).
// The compare is constant-time.
func totpValidate(secretB32, code string, t time.Time) (step uint64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	secret, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secretB32)))
	if err != nil {
		return 0, false
	}
	// Past-leaning window (current + previous step): tolerates clock drift/latency without accepting a
	// FUTURE step. Accepting now+1 both widened the live window to ~90s and — since the replay guard
	// records the matched step — locked out the legitimate code once wall-clock reached now+1.
	now := uint64(t.Unix()) / totpPeriod
	for _, c := range []uint64{now, now - 1} { // now is ~5.8e7, so now-1 never underflows
		if subtle.ConstantTimeCompare([]byte(hotp(secret, c)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// totpURI builds the otpauth:// provisioning URI (the consumer renders the QR from this string).
func totpURI(secretB32, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
