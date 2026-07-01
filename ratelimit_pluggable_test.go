package authx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// countingDenyLimiter is a consumer-supplied RateLimiter that ALWAYS throttles (Allow == false)
// and counts how many times it was consulted, with the keys it saw. It is the injected backend
// SetRateLimiters is supposed to install and route every gate through.
type countingDenyLimiter struct {
	mu    sync.Mutex
	calls int
	keys  []string
}

func (l *countingDenyLimiter) Allow(key string) bool {
	l.mu.Lock()
	l.calls++
	l.keys = append(l.keys, key)
	l.mu.Unlock()
	return false // always throttle
}

func (l *countingDenyLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func (l *countingDenyLimiter) sawKeyPrefix(prefix string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range l.keys {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// nopCreds is a minimal CredentialStore so LocalEnabled() (which requires a.creds != nil) is true
// and SetLocalEnabled(true) wires the local methods. PasswordSignup consults the per-IP limiter
// BEFORE any store call, so these methods must never be reached when the limiter denies — if they
// are (i.e. the limiter was bypassed), the test fails loudly.
type nopCreds struct {
	CredentialStore
	t *testing.T
}

func (c nopCreds) UserByEmail(string) (*AuthUser, error) {
	c.t.Fatal("creds.UserByEmail was reached: the per-IP limiter was NOT consulted (or did not deny)")
	return nil, ErrNoUser
}

func (c nopCreds) CreateLocalUser(string, string) (*AuthUser, error) {
	c.t.Fatal("creds.CreateLocalUser was reached: the per-IP limiter was bypassed")
	return nil, ErrNoUser
}

// TestPluggableRateLimiterNotClobbered verifies the central claim:
//
//  1. SetRateLimiters installs a consumer-supplied RateLimiter.
//  2. enableLimiters() (triggered by SetLocalEnabled(true)) does NOT overwrite it with the
//     built-in in-memory defaults.
//  3. The injected limiter is actually CONSULTED on a real request path (PasswordSignup ->
//     a.ipLimiter.Allow), and its verdict (deny) is honored: the request gets 429.
func TestPluggableRateLimiterNotClobbered(t *testing.T) {
	custom := &countingDenyLimiter{}

	a := &Authenticator{cfg: Config{
		SessionSecret: []byte("0123456789abcdef0123456789abcdef"),
		AppURL:        "https://app.example.com",
	}}
	a.SetCredentialStore(nopCreds{t: t})

	// Inject the custom limiter for BOTH the per-IP and per-account budgets.
	a.SetRateLimiters(custom, custom)

	// Sanity: the fields hold the exact instance we injected.
	if a.ipLimiter != custom || a.acctLimiter != custom {
		t.Fatalf("SetRateLimiters did not install the custom limiter: ip=%v acct=%v", a.ipLimiter, a.acctLimiter)
	}

	// Enabling local auth runs enableLimiters() (and enableWebauthn()). The claim under test:
	// enableLimiters must be a no-op when a limiter is already set, NOT clobber it with the
	// built-in *rateLimiter defaults.
	a.SetLocalEnabled(true)

	if a.ipLimiter != custom {
		t.Fatalf("enableLimiters CLOBBERED the consumer-supplied per-IP limiter; got %T", a.ipLimiter)
	}
	if a.acctLimiter != custom {
		t.Fatalf("enableLimiters CLOBBERED the consumer-supplied per-account limiter; got %T", a.acctLimiter)
	}
	if !a.LocalEnabled() {
		t.Fatal("LocalEnabled() should be true after SetLocalEnabled(true) with a credential store")
	}

	// Drive a real handler that gates on a.ipLimiter.Allow. PasswordSignup checks the per-IP
	// limiter at line 76, before any creds access. A valid email + strong password get PAST the
	// input-validation guards so the limiter is the thing that decides the outcome.
	body := `{"email":"newuser@example.com","password":"Str0ng-Passphrase-9x","name":"New User"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/password/signup", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:54321"
	rec := httptest.NewRecorder()

	a.PasswordSignup(a.newCtx(rec, req))

	// Assertion 1: the throttled request is rejected with 429.
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests from the injected deny-limiter; got %d (body=%q)",
			rec.Code, rec.Body.String())
	}

	// Assertion 2: the custom limiter's Allow was actually invoked.
	if custom.count() == 0 {
		t.Fatal("injected limiter Allow was never called: the interface was bypassed")
	}

	// And it was consulted via the per-IP gate (signup: prefix), proving the right limiter handle.
	if !custom.sawKeyPrefix("signup:") {
		t.Fatalf("injected per-IP limiter was not consulted with the signup gate key; keys=%v", custom.keys)
	}

	t.Logf("OK: injected limiter consulted %d time(s); 429 returned; ipLimiter is %T (custom retained)",
		custom.count(), a.ipLimiter)
}

// TestPluggableRateLimiterConsultedOnLogin is a second, independent path (PasswordLogin ->
// a.ipLimiter.Allow("login:"+ip)) to confirm the injected limiter is used consistently across
// handlers, not just on one endpoint.
func TestPluggableRateLimiterConsultedOnLogin(t *testing.T) {
	custom := &countingDenyLimiter{}
	a := &Authenticator{cfg: Config{
		SessionSecret: []byte("0123456789abcdef0123456789abcdef"),
		AppURL:        "https://app.example.com",
	}}
	a.SetCredentialStore(nopCreds{t: t})
	a.SetRateLimiters(custom, custom)
	a.SetLocalEnabled(true)

	if a.ipLimiter != custom {
		t.Fatalf("enableLimiters clobbered the per-IP limiter on the login path; got %T", a.ipLimiter)
	}

	body := `{"email":"someone@example.com","password":"whatever-long-enough"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/password/login", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.42:1111"
	rec := httptest.NewRecorder()

	a.PasswordLogin(a.newCtx(rec, req))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 from injected deny-limiter on login; got %d (body=%q)", rec.Code, rec.Body.String())
	}
	if custom.count() == 0 {
		t.Fatal("injected limiter Allow was never called on the login path")
	}
	if !custom.sawKeyPrefix("login:") {
		t.Fatalf("injected limiter not consulted with the login gate key; keys=%v", custom.keys)
	}
}
