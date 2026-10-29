package oidcprovider

import (
	"crypto/x509"
	"time"
)

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

// UseTestMetadataServer lets p fetch metadata documents from a test server: trusting its CA and
// allowing loopback addresses, which are refused otherwise.
func UseTestMetadataServer(p *Provider, roots *x509.CertPool) {
	p.cimd = newMetadataFetcher(p, roots, true)
}
