package oidcprovider

import "time"

// Test hooks for the external tests.

// SetClock replaces the clock of key rotation and the metadata cache (call before using p).
func SetClock(p *Provider, now func() time.Time) { p.now = now }

// MaintainKeys runs the clean-up's key upkeep now.
func MaintainKeys(p *Provider) error { return p.store.rotateKeys(false) }

// SigningKeyID is the id of the key p signs with now.
func SigningKeyID(p *Provider) string {
	if k := newest(p.store.currentKeys()); k != nil {
		return k.id
	}
	return ""
}
