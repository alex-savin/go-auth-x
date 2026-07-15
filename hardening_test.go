package authx

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestSanitizeNext_ControlBytes(t *testing.T) {
	for _, bad := range []string{"/\t/evil.com", "/\n/evil.com", "/\r/evil.com", "//evil.com", "/\\evil.com", "/\x00x", "/a\tb"} {
		if got := sanitizeNext(bad); got != "/" {
			t.Fatalf("sanitizeNext(%q) = %q, want \"/\" (open-redirect vector)", bad, got)
		}
	}
	for _, ok := range []string{"/", "/dashboard", "/a/b/c?q=1"} {
		if got := sanitizeNext(ok); got != ok {
			t.Fatalf("sanitizeNext(%q) = %q, want unchanged", ok, got)
		}
	}
}

func TestVerifyRejectsUnderStrengthKeyCookie(t *testing.T) {
	forge := func(key []byte) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, SessionClaims{RegisteredClaims: jwt.RegisteredClaims{
			Subject: "owner@example.com", Audience: jwt.ClaimStrings{audSession}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}})
		s, _ := tok.SignedString(key)
		return s
	}
	a := &Authenticator{cfg: Config{SessionSecret: []byte("short")}} // < 32 bytes
	if len(a.verifySecrets()) != 0 {
		t.Fatal("an under-strength primary secret must be dropped from the verify list")
	}
	if _, err := parseSessionMulti(a.verifySecrets(), forge([]byte("short"))); err == nil {
		t.Fatal("a cookie forged with a short key must be rejected")
	}
	if _, err := parseSessionMulti(a.verifySecrets(), forge([]byte(""))); err == nil {
		t.Fatal("a cookie forged with an empty key must be rejected")
	}
	if parseJWT([]byte("short"), forge([]byte("short")), &SessionClaims{}, audSession) == nil {
		t.Fatal("parseJWT must refuse an under-strength secret directly")
	}
}

func TestEnforcingWithSocialOnly(t *testing.T) {
	a := &Authenticator{}
	if a.enforcing() {
		t.Fatal("a bare authenticator must not enforce")
	}
	a.googleOAuth = &oauth2.Config{} // social configured; no OIDC, no SetLocalEnabled
	if !a.anySocialConfigured() {
		t.Fatal("precondition: social should be configured")
	}
	if !a.enforcing() {
		t.Fatal("a social-only deployment must still enforce the gate + CSRF")
	}
}

func TestIsMultiTenantMicrosoft(t *testing.T) {
	for _, m := range []string{"", "common", "COMMON", "organizations", "consumers", " common "} {
		if !isMultiTenantMicrosoft(m) {
			t.Fatalf("%q must be treated as multi-tenant (untrusted email)", m)
		}
	}
	for _, single := range []string{"contoso.onmicrosoft.com", "11111111-2222-3333-4444-555555555555"} {
		if isMultiTenantMicrosoft(single) {
			t.Fatalf("%q must be treated as single-tenant (trusted email)", single)
		}
	}
}

// --- password policy + pluggable breach checker ---

type fakeBreach struct {
	pwned bool
	err   error
}

func (f fakeBreach) Pwned(context.Context, string) (bool, error) { return f.pwned, f.err }

func TestPasswordPolicyError(t *testing.T) {
	a := &Authenticator{}
	if msg := a.passwordPolicyError(context.Background(), "short", "u@example.com"); msg == "" {
		t.Fatal("a too-short password must be rejected")
	}
	if msg := a.passwordPolicyError(context.Background(), "a-perfectly-fine-passphrase", "u@example.com"); msg != "" {
		t.Fatalf("a clean password must pass, got %q", msg)
	}
	a.breach = fakeBreach{pwned: true}
	if msg := a.passwordPolicyError(context.Background(), "a-perfectly-fine-passphrase", "u@example.com"); !strings.Contains(msg, "breach") {
		t.Fatalf("a breached password must be rejected, got %q", msg)
	}
	a.breach = fakeBreach{err: errors.New("hibp down")}
	if msg := a.passwordPolicyError(context.Background(), "a-perfectly-fine-passphrase", "u@example.com"); msg == "" {
		t.Fatal("a fail-closed checker error must block the password")
	}
}

func TestOriginAllowed_RefererFallback(t *testing.T) {
	a := &Authenticator{cfg: Config{AppURL: "https://app.example.com"}}
	ok := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	ok.Header.Set("Referer", "https://app.example.com/dashboard")
	if !a.originAllowed(ok) {
		t.Fatal("a matching Referer origin must be allowed when Origin is absent")
	}
	bad := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	bad.Header.Set("Referer", "https://evil.example.com/x")
	if a.originAllowed(bad) {
		t.Fatal("a mismatched Referer origin must be refused")
	}
}

func TestPasswordLengthCap(t *testing.T) {
	// bcrypt rejects >72 bytes, so the policy must too (else validation passes but hashing 500s).
	if msg := passwordStrengthError(strings.Repeat("a", 73), "u@x.com"); msg == "" {
		t.Fatal("a 73-byte password must be rejected")
	}
	if msg := passwordStrengthError(strings.Repeat("aB3$xY", 12), "u@x.com"); msg != "" { // exactly 72
		t.Fatalf("a 72-byte password must pass, got %q", msg)
	}
}

func TestMaskIPForRateLimit_V4Mapped(t *testing.T) {
	if got := maskIPForRateLimit("::ffff:203.0.113.7"); strings.HasSuffix(got, "/64") {
		t.Fatalf("an IPv4-mapped IPv6 address must be keyed as IPv4, got %q", got)
	}
	if got := maskIPForRateLimit("not-an-ip"); got != "not-an-ip" {
		t.Fatalf("an unparseable value must pass through unchanged, got %q", got)
	}
}

func TestVerifySecrets_Order(t *testing.T) {
	primary := []byte("primary-primary-primary-primary!")
	a := &Authenticator{cfg: Config{SessionSecret: primary, PreviousSessionSecrets: [][]byte{{}, []byte("prev-prev-prev-prev-prev-prev-32")}}}
	vs := a.verifySecrets()
	if len(vs) != 2 {
		t.Fatalf("empty previous secrets must be dropped, got %d entries", len(vs))
	}
	if string(vs[0]) != string(primary) {
		t.Fatal("the primary signing secret must come first")
	}
}

// --- session-secret rotation (multi-secret verify-list) ---

func TestSessionSecretRotation(t *testing.T) {
	newSecret := []byte("NEW-secret-NEW-secret-NEW-secret32")
	oldSecret := []byte("OLD-secret-OLD-secret-OLD-secret32")
	other := []byte("zzz-secret-zzz-secret-zzz-secret32")
	a := &Authenticator{cfg: Config{SessionSecret: newSecret, PreviousSessionSecrets: [][]byte{oldSecret}}}

	newTok, err := mintSession(newSecret, "local:u", "e@x.com", "N", "", "", nil, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldTok, _ := mintSession(oldSecret, "local:u", "e@x.com", "N", "", "", nil, time.Now(), time.Hour)
	badTok, _ := mintSession(other, "local:u", "e@x.com", "N", "", "", nil, time.Now(), time.Hour)

	if _, err := parseSessionMulti(a.verifySecrets(), newTok); err != nil {
		t.Fatalf("primary-signed session must verify: %v", err)
	}
	if _, err := parseSessionMulti(a.verifySecrets(), oldTok); err != nil {
		t.Fatalf("previous-secret-signed session must still verify during rollover: %v", err)
	}
	if _, err := parseSessionMulti(a.verifySecrets(), badTok); err == nil {
		t.Fatal("a session signed by an unknown secret must NOT verify")
	}
}

func TestNewRejectsShortPreviousSecret(t *testing.T) {
	_, err := New(nil, Config{
		SessionSecret:          []byte("0123456789abcdef0123456789abcdef"),
		PreviousSessionSecrets: [][]byte{[]byte("too-short")},
	})
	if err == nil {
		t.Fatal("New must reject a previous secret shorter than 32 bytes")
	}
}

// --- ban / disabled login gate ---

func TestLoginBlocked(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		u    AuthUser
		want bool
	}{
		{"clean", AuthUser{}, false},
		{"disabled", AuthUser{Disabled: true}, true},
		{"permanent ban", AuthUser{Banned: true}, true},
		{"timed ban active", AuthUser{Banned: true, BannedUntil: future}, true},
		{"timed ban expired", AuthUser{Banned: true, BannedUntil: past}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if blocked, _ := c.u.loginBlocked(); blocked != c.want {
				t.Fatalf("loginBlocked = %v, want %v", blocked, c.want)
			}
		})
	}
}

// --- trusted-origins allowlist (defense-in-depth, fails open) ---

func TestOriginAllowed(t *testing.T) {
	a := &Authenticator{cfg: Config{AppURL: "https://app.example.com", TrustedOrigins: []string{"https://admin.example.com"}}}
	mk := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/x", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	if !a.originAllowed(mk("")) {
		t.Fatal("absent Origin must fail OPEN (token stays primary)")
	}
	if !a.originAllowed(mk("https://app.example.com")) {
		t.Fatal("AppURL origin must be allowed")
	}
	if !a.originAllowed(mk("https://admin.example.com")) {
		t.Fatal("configured TrustedOrigins entry must be allowed")
	}
	if a.originAllowed(mk("https://evil.example.com")) {
		t.Fatal("a present, non-allowlisted Origin must be refused")
	}

	// With no allow-list configured at all, a present Origin still fails open.
	empty := &Authenticator{cfg: Config{}}
	if !empty.originAllowed(mk("https://anything.example.com")) {
		t.Fatal("empty allow-list must fail open")
	}
}

// --- IPv6 /64 rate-limit keying ---

func TestMaskIPForRateLimit(t *testing.T) {
	if got := maskIPForRateLimit("203.0.113.7"); got != "203.0.113.7" {
		t.Fatalf("IPv4 must be unchanged, got %q", got)
	}
	a := maskIPForRateLimit("2001:db8:abcd:1234:1:2:3:4")
	b := maskIPForRateLimit("2001:db8:abcd:1234:9:9:9:9")
	if a != b {
		t.Fatalf("two addresses in the same /64 must collapse to one key: %q vs %q", a, b)
	}
	if !strings.HasSuffix(a, "/64") {
		t.Fatalf("IPv6 key must be a /64 prefix, got %q", a)
	}
	c := maskIPForRateLimit("2001:db8:abcd:9999:1:2:3:4")
	if a == c {
		t.Fatal("addresses in different /64s must NOT share a key")
	}
}

// --- HIBP k-anonymity breach checker ---

func TestHIBPChecker(t *testing.T) {
	const pw = "correct horse battery staple"
	sum := sha1.Sum([]byte(pw))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		// Return the real suffix (count 42) plus a padding row and a decoy.
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:1\r\n" + suffix + ":42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"))
	}))
	defer srv.Close()

	h := &hibpChecker{client: srv.Client(), endpoint: srv.URL + "/range/", failOpen: true}
	pwned, err := h.Pwned(context.Background(), pw)
	if err != nil {
		t.Fatalf("Pwned errored: %v", err)
	}
	if !pwned {
		t.Fatal("a suffix present in the range response must be reported pwned")
	}
	// k-anonymity: ONLY the 5-char prefix is ever sent upstream.
	if !strings.HasSuffix(gotPath, "/range/"+prefix) {
		t.Fatalf("only the 5-char prefix may be sent, got path %q", gotPath)
	}
	if strings.Contains(gotPath, suffix) {
		t.Fatal("the hash suffix must never be sent upstream")
	}

	// A password whose suffix is absent is not pwned.
	notPwned, err := h.Pwned(context.Background(), "a-very-unlikely-unique-password-9271")
	if err != nil {
		t.Fatal(err)
	}
	if notPwned {
		t.Fatal("a suffix absent from the range must be reported not-pwned")
	}
}

// --- server-side session revocation through the gate ---

type fakeSessions struct{ revoked map[string]bool }

func (f *fakeSessions) RecordSession(SessionRecord) error  { return nil }
func (f *fakeSessions) IsRevoked(sid string) (bool, error) { return f.revoked[sid], nil }
func (f *fakeSessions) RevokeSession(sid string) error     { f.revoked[sid] = true; return nil }
func (f *fakeSessions) RevokeAllForUser(string) error      { return nil }
func (f *fakeSessions) ListSessionsForUser(string) ([]SessionRecord, error) {
	return nil, nil
}

func TestGateHTTP_Revocation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	fs := &fakeSessions{revoked: map[string]bool{}}
	a := &Authenticator{cfg: Config{SessionSecret: secret, AppURL: "https://app.example.com"}}
	a.enabled = true // make enforcing() true without a full OIDC setup
	a.sessions = fs

	tok, err := mintSessionWith(secret, SessionClaims{Email: "e@x.com", SID: "sid-1"}, "local:u", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	call := func() int {
		r := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
		w := httptest.NewRecorder()
		a.GateHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, r)
		return w.Code
	}
	if code := call(); code != http.StatusOK {
		t.Fatalf("a live session must pass the gate, got %d", code)
	}
	fs.RevokeSession("sid-1")
	if code := call(); code != http.StatusUnauthorized {
		t.Fatalf("a revoked session must be rejected by the gate, got %d", code)
	}
}

func TestHIBPFailOpen(t *testing.T) {
	// Point at a dead endpoint; a fail-open checker must swallow the error.
	h := &hibpChecker{client: &http.Client{Timeout: time.Second}, endpoint: "http://127.0.0.1:0/range/", failOpen: true}
	pwned, err := h.Pwned(context.Background(), "whatever")
	if err != nil || pwned {
		t.Fatalf("fail-open checker must return (false,nil) on transport error, got (%v,%v)", pwned, err)
	}
	// A fail-closed checker surfaces the error.
	h.failOpen = false
	if _, err := h.Pwned(context.Background(), "whatever"); err == nil {
		t.Fatal("fail-closed checker must surface a transport error")
	}
}
