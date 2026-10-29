package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"

	authx "github.com/alex-savin/go-auth-x"
)

// Signing keys. One key signs ID tokens: the newest one not retired. Every key in the store is
// published (the JWKS at Prefix + "/keys") until it is deleted, so a token signed with a key that
// was since retired still verifies until it has expired.
//
// The provider's clean-up rotates them: when the signing key is older than Config.KeyRotation a
// new one is added and the others are retired, and a key retired longer than Config.KeyGrace ago
// is deleted. Each replica caches the keys and reads them again every keyRefresh, so a key another
// replica added is published (and used) everywhere within that time; a verifier that meets an
// unknown key id fetches the JWKS again.

const (
	keyRefresh = 5 * time.Minute // how old the cached keys may get before they are read again
	keySkew    = 5 * time.Minute // clock skew allowed for when a retired key may go
)

type signingKey struct {
	id      string
	key     *rsa.PrivateKey
	at      time.Time // created
	retired time.Time // zero while it signs
}

func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k signingKey) Key() any                                    { return k.key }
func (k signingKey) ID() string                                  { return k.id }

type publicKey struct{ signingKey }

func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return &k.key.PublicKey }

// newest is the key that signs: the newest one not retired, ties broken by id so that every
// replica picks the same one. Nil when every key is retired.
func newest(keys []signingKey) *signingKey {
	var best *signingKey
	for i := range keys {
		k := &keys[i]
		if !k.retired.IsZero() {
			continue
		}
		if best == nil || k.at.After(best.at) || (k.at.Equal(best.at) && k.id > best.id) {
			best = k
		}
	}
	return best
}

// readKeys reads the stored keys; one that doesn't parse is skipped.
func (s *storage) readKeys() ([]signingKey, error) {
	stored, err := s.st().OAuthSigningKeys()
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: signing keys: %w", err)
	}
	keys := make([]signingKey, 0, len(stored))
	for _, k := range stored {
		blk, _ := pem.Decode(k.PrivatePEM)
		if blk == nil {
			continue
		}
		pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		rk, ok := pk.(*rsa.PrivateKey)
		if err != nil || !ok {
			continue
		}
		sk := signingKey{id: k.ID, key: rk, at: k.CreatedAt}
		if k.RetiredAt != nil {
			sk.retired = *k.RetiredAt
		}
		keys = append(keys, sk)
	}
	return keys, nil
}

// addKey generates a key and stores it, created at now.
func (s *storage) addKey(now time.Time) error {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		return err
	}
	k := &authx.OAuthSigningKey{ID: randomID(12), Algorithm: "RS256", PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), CreatedAt: now.UTC()}
	if err := s.st().AddOAuthSigningKey(k); err != nil {
		return fmt.Errorf("oidcprovider: saving a signing key: %w", err)
	}
	return nil
}

// loadKeys reads the keys into the cache, creating one when none is in use (the first start).
func (s *storage) loadKeys() error {
	keys, err := s.readKeys()
	if err != nil {
		return err
	}
	if newest(keys) == nil {
		if err := s.addKey(s.p.now()); err != nil {
			return err
		}
		if keys, err = s.readKeys(); err != nil {
			return err
		}
	}
	s.kmu.Lock()
	s.keys, s.keysAt = keys, s.p.now()
	s.kmu.Unlock()
	return nil
}

// currentKeys returns the cached keys, read again first when the cache is older than keyRefresh.
// One caller reads them; the others meanwhile carry on with the cached ones.
func (s *storage) currentKeys() []signingKey {
	now := s.p.now()
	s.kmu.Lock()
	keys, stale := s.keys, now.Sub(s.keysAt) >= keyRefresh
	if stale {
		s.keysAt = now
	}
	s.kmu.Unlock()
	if !stale {
		return keys
	}
	if err := s.loadKeys(); err != nil {
		s.p.cfg.Logger.Warn("oidcprovider: reading the signing keys failed", "err", err)
		return keys
	}
	s.kmu.Lock()
	defer s.kmu.Unlock()
	return s.keys
}

// rotateKeys is the key upkeep, run by the clean-up (and by RotateKeys, with force): it adds a new
// key when the signing one is older than Config.KeyRotation, retires every other key in use,
// deletes keys retired longer than Config.KeyGrace ago, and reloads the cache.
//
// Replicas sharing the store may run it at the same time. Each re-reads the keys after adding its
// own and keeps only the newest signing, so they settle on one key. Two replicas rotating at once
// leave an extra key, retired straight away and published for the grace period like any other —
// harmless. A replica that has not reloaded yet signs with the previous key for up to keyRefresh,
// which stays published, so its tokens verify.
func (s *storage) rotateKeys(force bool) error {
	now := s.p.now()
	keys, err := s.readKeys()
	if err != nil {
		return err
	}
	cur := newest(keys)
	if force || cur == nil || (s.p.cfg.KeyRotation > 0 && now.Sub(cur.at) >= s.p.cfg.KeyRotation) {
		if err := s.addKey(now); err != nil {
			return err
		}
		if keys, err = s.readKeys(); err != nil {
			return err
		}
		if cur = newest(keys); cur == nil {
			return errors.New("oidcprovider: the new signing key is missing")
		}
	}
	var errs []error
	for _, k := range keys {
		switch {
		case k.retired.IsZero() && k.id != cur.id:
			if err := s.st().RetireOAuthSigningKey(k.id, now.UTC()); err != nil && !errors.Is(err, authx.ErrOAuthNotFound) {
				errs = append(errs, err)
			}
		case !k.retired.IsZero() && now.Sub(k.retired) >= s.p.cfg.KeyGrace:
			if err := s.st().DeleteOAuthSigningKey(k.id); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := s.loadKeys(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// RotateKeys adds a new signing key now and retires the others, which stay published for
// Config.KeyGrace (e.g. after a key may have leaked; rotation is otherwise automatic). Other
// replicas start signing with the new key within a few minutes.
func (p *Provider) RotateKeys(context.Context) error { return p.store.rotateKeys(true) }

func (s *storage) SigningKey(context.Context) (op.SigningKey, error) {
	k := newest(s.currentKeys())
	if k == nil {
		return nil, errors.New("no signing key")
	}
	return *k, nil
}

func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet publishes every key not yet deleted: the signing one and those retired within the grace.
func (s *storage) KeySet(context.Context) ([]op.Key, error) {
	keys := s.currentKeys()
	out := make([]op.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, publicKey{k})
	}
	return out, nil
}
