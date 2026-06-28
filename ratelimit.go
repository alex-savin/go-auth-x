package authx

import (
	"sync"
	"time"
)

// RateLimiter throttles auth attempts keyed by an arbitrary string (a client IP or an account
// email). Allow records ONE attempt for key and reports whether it remains within budget (false =
// throttle). Implementations MUST be safe for concurrent use. The built-in default is in-memory and
// per-process; for a multi-replica deployment supply a shared-store (e.g. Redis) implementation via
// SetRateLimiters so the budget is coherent across replicas.
type RateLimiter interface {
	Allow(key string) bool
}

// SetRateLimiters overrides the per-IP and per-account limiters with custom (e.g. Redis-backed)
// backends. Call it during setup, BEFORE auth is enabled — once set, the built-in in-memory
// defaults (and their GC ticker) are not installed. Both arguments are required.
func (a *Authenticator) SetRateLimiters(perIP, perAccount RateLimiter) {
	a.ipLimiter, a.acctLimiter = perIP, perAccount
}

// rateLimiter is the built-in in-memory sliding-window RateLimiter, keyed by an arbitrary string.
// Safe for concurrent use; per-process only (use SetRateLimiters for horizontal scaling).
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	window time.Duration
	limit  int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: make(map[string][]time.Time), window: window, limit: limit}
}

// enableLimiters lazily installs the per-IP and per-account limiters and starts a GC ticker.
// Called when in-app auth is turned on. A no-op if the consumer already supplied limiters via
// SetRateLimiters (they own their backend's expiry, so no GC ticker is started).
func (a *Authenticator) enableLimiters() {
	if a.ipLimiter != nil {
		return
	}
	ip := newRateLimiter(20, 5*time.Minute)    // total auth attempts per IP
	acct := newRateLimiter(10, 15*time.Minute) // request-mail attempts per account
	a.ipLimiter, a.acctLimiter = ip, acct
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			ip.gc()
			acct.gc()
		}
	}()
}

// Allow records an attempt for key and reports whether it is within the limit.
func (r *rateLimiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-r.window)
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.hits[key][:0] // in-place filter (append never overtakes the read index)
	for _, t := range r.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		r.hits[key] = kept
		return false
	}
	r.hits[key] = append(kept, now)
	return true
}

// gc drops empty/expired buckets; call periodically from a background ticker.
func (r *rateLimiter) gc() {
	cutoff := time.Now().Add(-r.window)
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, ts := range r.hits {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(r.hits, k)
		} else {
			r.hits[k] = kept
		}
	}
}
