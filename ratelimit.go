package authx

import (
	"sync"
	"time"
)

// rateLimiter is a small in-memory sliding-window limiter keyed by an arbitrary string
// (per-IP or per-account email). Safe for concurrent use. The single-replica deployment
// makes the in-memory state coherent; horizontal scaling would require a shared store
// (Postgres/Redis) instead.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	window time.Duration
	limit  int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: make(map[string][]time.Time), window: window, limit: limit}
}

// enableLimiters lazily creates the per-IP and per-account limiters and starts a GC ticker.
// Called when in-app auth is turned on.
func (a *Authenticator) enableLimiters() {
	if a.ipLimiter != nil {
		return
	}
	a.ipLimiter = newRateLimiter(20, 5*time.Minute)   // total auth attempts per IP
	a.acctLimiter = newRateLimiter(10, 15*time.Minute) // request-mail attempts per account
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			a.ipLimiter.gc()
			a.acctLimiter.gc()
		}
	}()
}

// allow records an attempt for key and reports whether it is within the limit.
func (r *rateLimiter) allow(key string) bool {
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
