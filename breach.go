package authx

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// BreachChecker reports whether a candidate password appears in a known-breach corpus. It is consulted
// on signup, password reset, and password change, in ADDITION to the embedded common-password list.
//
// A non-nil error means the check could not be COMPLETED (e.g. the upstream service was unreachable).
// The checker itself decides fail-open vs fail-closed: a fail-open checker swallows transport errors
// and returns (false, nil); a fail-closed checker returns the error, and the engine then refuses the
// password rather than let a possibly-breached one through.
type BreachChecker interface {
	Pwned(ctx context.Context, password string) (bool, error)
}

// SetBreachChecker installs an optional password-breach checker (e.g. the HIBP k-anonymity checker).
// Pass nil to disable. Also enabled at boot via HIBP_BREACH_CHECK=true (see NewHIBPBreachChecker).
func (a *Authenticator) SetBreachChecker(b BreachChecker) { a.breach = b }

// passwordPolicyError runs the offline strength checks (length/common/email) and then, if a breach
// checker is configured, the breach check. It returns a user-facing rejection reason, or "".
func (a *Authenticator) passwordPolicyError(ctx context.Context, pw, email string) string {
	if msg := passwordStrengthError(pw, email); msg != "" {
		return msg
	}
	if a.breach != nil {
		pwned, err := a.breach.Pwned(ctx, pw)
		if err != nil {
			// A fail-closed checker surfaced a transport error: refuse rather than admit an unscreened
			// password. (A fail-open checker never gets here — it returns nil.)
			return "we couldn't verify your password right now — please try again"
		}
		if pwned {
			return "that password has appeared in a data breach — choose a different one"
		}
	}
	return ""
}

// hibpChecker screens passwords against Have I Been Pwned's Pwned Passwords range API using k-anonymity:
// only the first 5 hex chars of the SHA-1 are sent; the full hash never leaves the process.
type hibpChecker struct {
	client   *http.Client
	endpoint string // range API base, default https://api.pwnedpasswords.com/range/
	failOpen bool   // on a transport/HTTP error: true = allow (return false,nil); false = surface the error
}

// NewHIBPBreachChecker returns a fail-open HIBP checker (a HIBP outage degrades to the embedded list
// rather than blocking signups). It sends the Add-Padding header to blunt response-size analysis and
// times out quickly so a slow upstream can't stall the signup/reset path.
func NewHIBPBreachChecker() *hibpChecker {
	return &hibpChecker{
		client:   &http.Client{Timeout: 3 * time.Second},
		endpoint: "https://api.pwnedpasswords.com/range/",
		failOpen: true,
	}
}

func (h *hibpChecker) Pwned(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.endpoint+prefix, nil)
	if err != nil {
		return h.onError(err)
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "go-auth-x")
	resp, err := h.client.Do(req)
	if err != nil {
		return h.onError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return h.onError(fmt.Errorf("hibp: unexpected status %d", resp.StatusCode))
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		// Each line is "SUFFIX:count"; padding rows carry a count of 0 and are ignored.
		colon := strings.IndexByte(line, ':')
		if colon != 35 { // 35-hex-char suffix
			continue
		}
		candidate := strings.ToUpper(strings.TrimSpace(line[:colon]))
		count := strings.TrimSpace(line[colon+1:])
		if count == "0" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(suffix)) == 1 {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return h.onError(err)
	}
	return false, nil
}

func (h *hibpChecker) onError(err error) (bool, error) {
	if h.failOpen {
		return false, nil
	}
	return false, err
}
