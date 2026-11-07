package oidcprovider

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
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
//
// At rest each key is sealed with AES-GCM under a key derived from Config.CryptoKey, bound to its
// id, so a copy of the store alone can't sign tokens. Keys stored in the clear (v0.10 and earlier)
// still load and are sealed by the next upkeep. A key the CryptoKey can't open (it changed, or
// replicas disagree on it) is ignored, and deleted once it would have expired anyway.

const (
	keyRefresh = 5 * time.Minute // how old the cached keys may get before they are read again
	keySkew    = 5 * time.Minute // clock skew allowed for when a retired key may go
)

type signingKey struct {
	id      string
	key     *rsa.PrivateKey
	at      time.Time // created
	retired time.Time // zero while it signs
	plain   bool      // stored in the clear (before keys were sealed): the upkeep seals it
}

// sealedPrefix marks a sealed key: the prefix, then the GCM nonce, then the sealed PEM.
var sealedPrefix = []byte("authx-sealed-v1:")

// seal encrypts a key's PEM for storage, with its id as additional data.
func (s *storage) seal(id string, pemBytes []byte) ([]byte, error) {
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(slices.Clip(sealedPrefix), nonce...)
	return gcm.Seal(out, nonce, pemBytes, []byte(id)), nil
}

// open returns a stored key's PEM: unsealed, or as stored when it predates sealing (plain).
func (s *storage) open(id string, stored []byte) (pemBytes []byte, plain bool, err error) {
	if bytes.HasPrefix(stored, []byte("-----BEGIN")) {
		return stored, true, nil
	}
	rest, ok := bytes.CutPrefix(stored, sealedPrefix)
	if !ok {
		return nil, false, errors.New("not a sealed key")
	}
	gcm, err := s.gcm()
	if err != nil {
		return nil, false, err
	}
	if len(rest) < gcm.NonceSize() {
		return nil, false, errors.New("sealed key too short")
	}
	pemBytes, err = gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], []byte(id))
	return pemBytes, false, err
}

func (s *storage) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// keyPEM renders a key as the PKCS#8 PEM block that gets sealed.
func keyPEM(rk *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
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

// readKeys reads the stored keys, returning apart those that can't be opened or parsed.
func (s *storage) readKeys() (keys []signingKey, unreadable []authx.OAuthSigningKey, err error) {
	stored, err := s.st().OAuthSigningKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("oidcprovider: signing keys: %w", err)
	}
	keys = make([]signingKey, 0, len(stored))
	for _, k := range stored {
		rk, plain, err := s.parseKey(k)
		if err != nil {
			unreadable = append(unreadable, k)
			continue
		}
		sk := signingKey{id: k.ID, key: rk, at: k.CreatedAt, plain: plain}
		if k.RetiredAt != nil {
			sk.retired = *k.RetiredAt
		}
		keys = append(keys, sk)
	}
	return keys, unreadable, nil
}

func (s *storage) parseKey(k authx.OAuthSigningKey) (*rsa.PrivateKey, bool, error) {
	pemBytes, plain, err := s.open(k.ID, k.PrivatePEM)
	if err != nil {
		return nil, false, err
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, false, errors.New("no PEM block")
	}
	pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, false, err
	}
	rk, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, false, errors.New("not an RSA key")
	}
	return rk, plain, nil
}

// storeKey seals k and stores it (adding it, or replacing the stored key with its id).
func (s *storage) storeKey(k signingKey) error {
	pemBytes, err := keyPEM(k.key)
	if err != nil {
		return err
	}
	sealed, err := s.seal(k.id, pemBytes)
	if err != nil {
		return err
	}
	rec := &authx.OAuthSigningKey{ID: k.id, Algorithm: "RS256", PrivatePEM: sealed, CreatedAt: k.at.UTC()}
	if !k.retired.IsZero() {
		t := k.retired.UTC()
		rec.RetiredAt = &t
	}
	if err := s.st().AddOAuthSigningKey(rec); err != nil {
		return fmt.Errorf("oidcprovider: saving a signing key: %w", err)
	}
	return nil
}

// addKey generates a key and stores it, created at now.
func (s *storage) addKey(now time.Time) error {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	return s.storeKey(signingKey{id: randomID(12), key: rk, at: now})
}

// loadKeys reads the keys into the cache, creating one when none is in use (the first start).
func (s *storage) loadKeys() error {
	keys, _, err := s.readKeys()
	if err != nil {
		return err
	}
	if newest(keys) == nil {
		if err := s.addKey(s.p.now()); err != nil {
			return err
		}
		if keys, _, err = s.readKeys(); err != nil {
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
	keys, unreadable, err := s.readKeys()
	if err != nil {
		return err
	}
	cur := newest(keys)
	if force || cur == nil || (s.p.cfg.KeyRotation > 0 && now.Sub(cur.at) >= s.p.cfg.KeyRotation) {
		if err := s.addKey(now); err != nil {
			return err
		}
		if keys, unreadable, err = s.readKeys(); err != nil {
			return err
		}
		if cur = newest(keys); cur == nil {
			return errors.New("oidcprovider: the new signing key is missing")
		}
	}
	var errs []error
	for _, k := range keys {
		if !k.retired.IsZero() && now.Sub(k.retired) >= s.p.cfg.KeyGrace {
			if err := s.st().DeleteOAuthSigningKey(k.id); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if k.plain { // stored in the clear before keys were sealed: seal it in place
			if err := s.storeKey(k); err != nil {
				errs = append(errs, err)
			}
		}
		if k.retired.IsZero() && k.id != cur.id {
			if err := s.st().RetireOAuthSigningKey(k.id, now.UTC()); err != nil && !errors.Is(err, authx.ErrOAuthNotFound) {
				errs = append(errs, err)
			}
		}
	}
	errs = append(errs, s.dropUnreadable(unreadable, now)...)
	if err := s.loadKeys(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// dropUnreadable deals with keys this CryptoKey can't open: never usable here, they are reported,
// and deleted once they would have been deleted had they been readable — retired longer than
// KeyGrace ago, or (still signing somewhere) older than a rotation, the grace and an upkeep's slack.
func (s *storage) dropUnreadable(keys []authx.OAuthSigningKey, now time.Time) []error {
	if len(keys) == 0 {
		return nil
	}
	ids := make([]string, 0, len(keys))
	var errs []error
	for _, k := range keys {
		ids = append(ids, k.ID)
		expired := false
		switch {
		case k.RetiredAt != nil:
			expired = now.Sub(*k.RetiredAt) >= s.p.cfg.KeyGrace
		case s.p.cfg.KeyRotation > 0:
			expired = now.Sub(k.CreatedAt) >= s.p.cfg.KeyRotation+s.p.cfg.KeyGrace+time.Hour
		}
		if expired {
			if err := s.st().DeleteOAuthSigningKey(k.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	s.p.cfg.Logger.Warn("oidcprovider: ignoring signing keys this CryptoKey can't open (did it change, or do replicas disagree on it?)", "keys", ids)
	return errs
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
