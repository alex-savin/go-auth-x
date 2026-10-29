package oidcprovider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// clock is a settable clock, safe for concurrent use.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now()} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// idToken runs a flow asking for openid and returns the ID token.
func (h *harness) idToken(clientID string) string {
	h.t.Helper()
	id := h.authorize(clientID, url.Values{"scope": {"openid tree:read"}})
	next, err := h.p.Approve(context.Background(), id, h.user.Sub, oidcprovider.Decision{})
	if err != nil {
		h.t.Fatal(err)
	}
	st, tok := h.exchange(clientID, h.code(next))
	s, _ := tok["id_token"].(string)
	if st != 200 || s == "" {
		h.t.Fatalf("token = %d %v", st, tok)
	}
	return s
}

// jwks fetches the published keys.
func (h *harness) jwks() jose.JSONWebKeySet {
	h.t.Helper()
	res, err := http.Get(h.srv.URL + "/oauth/keys")
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		h.t.Fatal(err)
	}
	return set
}

// keyID is the id of the key that signed tok.
func keyID(t *testing.T, tok string) string {
	t.Helper()
	jws, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		t.Fatalf("parse %q: %v", tok, err)
	}
	return jws.Signatures[0].Header.KeyID
}

// verifies reports whether tok's signature checks out against the published keys.
func (h *harness) verifies(tok string) bool {
	h.t.Helper()
	jws, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		h.t.Fatal(err)
	}
	set := h.jwks()
	keys := set.Key(jws.Signatures[0].Header.KeyID)
	if len(keys) != 1 {
		return false
	}
	_, err = jws.Verify(keys[0].Key)
	return err == nil
}

// activeKeys counts the stored keys not retired.
func (h *harness) activeKeys() int {
	h.t.Helper()
	keys, err := h.store.OAuthSigningKeys()
	if err != nil {
		h.t.Fatal(err)
	}
	n := 0
	for _, k := range keys {
		if k.RetiredAt == nil {
			n++
		}
	}
	return n
}

func TestKeyRotation(t *testing.T) {
	h := setup(t)
	clk := newClock()
	oidcprovider.SetClock(h.p, clk.Now)
	cid := h.publicClient()
	h.signIn(h.web, "u@x.com", "correct horse battery staple")

	tok1 := h.idToken(cid)
	k1 := oidcprovider.SigningKeyID(h.p)
	if keyID(t, tok1) != k1 || !h.verifies(tok1) {
		t.Fatalf("the first token must be signed with %s and verify", k1)
	}

	// A fresh key is not rotated.
	clk.Add(89 * 24 * time.Hour)
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	if k := oidcprovider.SigningKeyID(h.p); k != k1 {
		t.Fatalf("a key younger than KeyRotation was replaced: %s", k)
	}

	// Past KeyRotation, a new key signs; the old one is retired but still published.
	clk.Add(2 * 24 * time.Hour)
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	k2 := oidcprovider.SigningKeyID(h.p)
	if k2 == k1 || k2 == "" {
		t.Fatalf("the key was not rotated: %q", k2)
	}
	if n := h.activeKeys(); n != 1 {
		t.Fatalf("%d keys in use, want 1", n)
	}
	if len(h.jwks().Keys) != 2 {
		t.Fatalf("the JWKS must publish the new and the retired key: %+v", h.jwks().Keys)
	}
	if !h.verifies(tok1) {
		t.Fatal("a token signed before the rotation must still verify")
	}
	tok2 := h.idToken(cid)
	if keyID(t, tok2) != k2 || !h.verifies(tok2) {
		t.Fatalf("a token after the rotation must be signed with %s", k2)
	}

	// Within the grace (default 24 hours) the retired key stays; after it, it goes.
	clk.Add(23 * time.Hour)
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	if !h.verifies(tok1) {
		t.Fatal("the retired key must stay published during the grace")
	}
	clk.Add(2 * time.Hour)
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	if h.verifies(tok1) {
		t.Fatal("the retired key must be deleted after the grace")
	}
	if set := h.jwks(); len(set.Keys) != 1 || set.Keys[0].KeyID != k2 || !h.verifies(tok2) {
		t.Fatalf("only the signing key must remain: %+v", set.Keys)
	}

	// RotateKeys forces a rotation.
	if err := h.p.RotateKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k := oidcprovider.SigningKeyID(h.p); k == k2 || h.activeKeys() != 1 || !h.verifies(tok2) {
		t.Fatalf("RotateKeys: signing %s, %d in use", k, h.activeKeys())
	}
}

func TestKeyRotationNever(t *testing.T) {
	h := setup(t, func(c *oidcprovider.Config) { c.KeyRotation = -1 })
	clk := newClock()
	oidcprovider.SetClock(h.p, clk.Now)
	k1 := oidcprovider.SigningKeyID(h.p)
	clk.Add(1000 * 24 * time.Hour)
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	if k := oidcprovider.SigningKeyID(h.p); k != k1 {
		t.Fatalf("KeyRotation < 0 must never rotate, got %s", k)
	}
}

// Replicas share the store: one replica's rotation reaches the other when its cache refreshes,
// and replicas rotating at once settle on one signing key.
func TestKeyRotationReplicas(t *testing.T) {
	h := setup(t)
	clk1, clk2 := newClock(), newClock()
	oidcprovider.SetClock(h.p, clk1.Now)
	p2, err := oidcprovider.New(context.Background(), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p2.Close)
	oidcprovider.SetClock(p2, clk2.Now)
	k1 := oidcprovider.SigningKeyID(h.p)
	if k := oidcprovider.SigningKeyID(p2); k != k1 {
		t.Fatalf("a second replica must use the existing key, got %s want %s", k, k1)
	}

	if err := h.p.RotateKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	k2 := oidcprovider.SigningKeyID(h.p)
	if k := oidcprovider.SigningKeyID(p2); k != k1 {
		t.Fatalf("the other replica reads the keys again only when its cache is old: %s", k)
	}
	clk2.Add(6 * time.Minute)
	if k := oidcprovider.SigningKeyID(p2); k != k2 {
		t.Fatalf("the other replica must pick up the new key: %s, want %s", k, k2)
	}

	// Both rotating at once: an extra key, but one signs, on both.
	var wg sync.WaitGroup
	for _, p := range []*oidcprovider.Provider{h.p, p2, h.p, p2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.RotateKeys(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	if err := oidcprovider.MaintainKeys(p2); err != nil {
		t.Fatal(err)
	}
	if n := h.activeKeys(); n != 1 {
		t.Fatalf("%d keys in use after concurrent rotations, want 1", n)
	}
	if a, b := oidcprovider.SigningKeyID(h.p), oidcprovider.SigningKeyID(p2); a != b {
		t.Fatalf("replicas sign with different keys: %s, %s", a, b)
	}
}

// Rotation, cache refreshes, signing and publishing run concurrently (go test -race).
func TestKeyRotationConcurrent(t *testing.T) {
	h := setup(t)
	clk := newClock()
	oidcprovider.SetClock(h.p, clk.Now)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				switch i % 4 {
				case 0:
					if err := h.p.RotateKeys(context.Background()); err != nil {
						t.Error(err)
					}
				case 1:
					clk.Add(3 * time.Minute)
					if err := oidcprovider.MaintainKeys(h.p); err != nil {
						t.Error(err)
					}
				case 2:
					if oidcprovider.SigningKeyID(h.p) == "" {
						t.Error("no signing key")
					}
				case 3:
					res, err := http.Get(h.srv.URL + "/oauth/keys")
					if err != nil {
						t.Error(err)
						continue
					}
					res.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
	if err := oidcprovider.MaintainKeys(h.p); err != nil {
		t.Fatal(err)
	}
	if n := h.activeKeys(); n != 1 {
		t.Fatalf("%d keys in use, want 1", n)
	}
}
