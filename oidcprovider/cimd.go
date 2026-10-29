package oidcprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	authx "github.com/alex-savin/go-auth-x"
)

// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document, used by the MCP
// authorization spec): instead of registering, a client uses an https URL as its client_id, and
// the provider fetches its metadata from that URL. Such a client is public (PKCE, no secret) and
// is never stored: the document is cached in memory for a while and fetched again after.
//
// Fetching a URL a stranger names is server-side request forgery waiting to happen, so the fetch
// resolves the host itself, refuses any address that is not public (private, loopback,
// link-local, CGNAT, multicast and the like, IPv4 and IPv6), dials only the address it checked
// (so DNS rebinding can't swap in another between the check and the connection), checks the
// connected address again, ignores proxy settings, and limits time, size and redirects.

const (
	metadataTimeout  = 5 * time.Second
	metadataMaxBytes = 64 << 10
	metadataMinAge   = 5 * time.Minute
	metadataMaxAge   = 24 * time.Hour
	metadataDefAge   = time.Hour
	metadataFailAge  = time.Minute // a failed fetch is not tried again for this long
	metadataCacheMax = 1000
)

var errMetadata = errors.New("oidcprovider: client metadata document refused")

// metadataDoc is a client's metadata document: RFC 7591 client metadata plus its client_id.
type metadataDoc struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// metadataFetcher fetches and caches clients' metadata documents.
type metadataFetcher struct {
	p      *Provider
	http   *http.Client
	public func(netip.Addr) bool // whether an address may be fetched from

	mu    sync.Mutex
	cache map[string]metadataEntry
}

type metadataEntry struct {
	c   *authx.OAuthClient // nil: the fetch failed
	err error
	exp time.Time
}

// newMetadataFetcher builds the fetcher. roots and loopback are for tests only: the CA of a test
// server, and permission to fetch from 127.0.0.1 / ::1.
func newMetadataFetcher(p *Provider, roots *x509.CertPool, loopback bool) *metadataFetcher {
	f := &metadataFetcher{p: p, cache: map[string]metadataEntry{}, public: publicAddr}
	if loopback {
		f.public = func(a netip.Addr) bool { return publicAddr(a) || a.Unmap().IsLoopback() }
	}
	d := &net.Dialer{
		Timeout: metadataTimeout,
		// The address actually connected to, checked once more.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !f.public(ap.Addr()) {
				return fmt.Errorf("%w: address %s is not public", errMetadata, address)
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy: nil, // never through a proxy: the address check is about where the request goes
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ip, err := f.resolve(ctx, addr)
			if err != nil {
				return nil, err
			}
			return d.DialContext(ctx, network, ip.String())
		},
		TLSClientConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    metadataTimeout,
		ResponseHeaderTimeout:  metadataTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
	}
	f.http = &http.Client{
		Transport: tr,
		Timeout:   metadataTimeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 3 || r.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to %s", errMetadata, r.URL.Redacted())
			}
			return nil
		},
	}
	return f
}

// resolve looks up addr's host and returns the address to dial, refusing the host if any of its
// addresses is not public (a name that also points inward is not trusted either way).
func (f *metadataFetcher) resolve(ctx context.Context, addr string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: %s has no address", errMetadata, host)
	}
	for _, ip := range ips {
		if !f.public(ip) {
			return netip.AddrPort{}, fmt.Errorf("%w: %s resolves to %s, which is not public", errMetadata, host, ip)
		}
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(pn)), nil
}

// blockedPrefixes are special-purpose ranges netip's predicates don't cover (RFC 6890 and kin).
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network"
		"100.64.0.0/10",   // carrier-grade NAT (RFC 6598)
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"240.0.0.0/4",     // reserved, and the broadcast address
		"::/96",           // IPv4-compatible (deprecated)
		"64:ff9b::/96",    // NAT64, which could reach a private IPv4 address
		"64:ff9b:1::/48",  // local NAT64
		"100::/64",        // discard
		"2001::/32",       // Teredo
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4, which embeds an IPv4 address
		"fec0::/10",       // site-local (deprecated)
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// publicAddr reports whether a is a public unicast address, one a metadata document may be
// fetched from: not private, loopback, link-local, multicast, unspecified, CGNAT or another
// special-purpose range. An IPv4-mapped IPv6 address is judged as its IPv4 address.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// isMetadataURL reports whether a client_id is a metadata document's URL: https, with a host and
// a path, no fragment, no credentials and no dot segments.
func isMetadataURL(id string) bool {
	if !strings.HasPrefix(id, "https://") || len(id) > 2000 {
		return false
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(id, "#") {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// client returns the client with this id: from its metadata document when it is one's URL (and
// Config.ClientMetadataDocuments is on), otherwise from the store.
func (p *Provider) client(ctx context.Context, id string) (*authx.OAuthClient, error) {
	if p.metadataClient(id) {
		return p.cimd.get(ctx, id)
	}
	return p.cfg.Store.OAuthClient(id)
}

// metadataClient reports whether the client with this id is described by a metadata document.
func (p *Provider) metadataClient(id string) bool {
	return p.cfg.ClientMetadataDocuments && isMetadataURL(id)
}

// get returns the client described at rawURL, from the cache or fetched.
func (f *metadataFetcher) get(ctx context.Context, rawURL string) (*authx.OAuthClient, error) {
	now := f.p.now()
	f.mu.Lock()
	e, ok := f.cache[rawURL]
	f.mu.Unlock()
	if ok && now.Before(e.exp) {
		if e.c == nil {
			return nil, e.err
		}
		c := *e.c
		return &c, nil
	}
	c, age, err := f.fetch(ctx, rawURL)
	if err != nil {
		f.p.cfg.Logger.Warn("oidcprovider: client metadata document refused", "client", rawURL, "err", err)
		err = fmt.Errorf("%w: %w", authx.ErrOAuthNotFound, err)
		f.put(rawURL, metadataEntry{err: err, exp: now.Add(metadataFailAge)}, now)
		return nil, err
	}
	f.put(rawURL, metadataEntry{c: c, exp: now.Add(age)}, now)
	out := *c
	return &out, nil
}

// cached returns the client described at rawURL if the cache holds it, without fetching.
func (f *metadataFetcher) cached(rawURL string) *authx.OAuthClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.cache[rawURL]; ok && e.c != nil {
		c := *e.c
		return &c
	}
	return nil
}

// put caches an entry, making room when the cache is full: first by dropping expired entries,
// then the one expiring soonest.
func (f *metadataFetcher) put(rawURL string, e metadataEntry, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.cache[rawURL]; !ok && len(f.cache) >= metadataCacheMax {
		for k, v := range f.cache {
			if !now.Before(v.exp) {
				delete(f.cache, k)
			}
		}
		for len(f.cache) >= metadataCacheMax {
			var oldest string
			for k, v := range f.cache {
				if oldest == "" || v.exp.Before(f.cache[oldest].exp) {
					oldest = k
				}
			}
			delete(f.cache, oldest)
		}
	}
	f.cache[rawURL] = e
}

// fetch gets and checks the document at rawURL, returning the client and how long to cache it.
func (f *metadataFetcher) fetch(ctx context.Context, rawURL string) (*authx.OAuthClient, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := f.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: status %d", errMetadata, res.StatusCode)
	}
	mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
		return nil, 0, fmt.Errorf("%w: content type %q is not JSON", errMetadata, res.Header.Get("Content-Type"))
	}
	if res.ContentLength > metadataMaxBytes {
		return nil, 0, fmt.Errorf("%w: larger than %d bytes", errMetadata, metadataMaxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, metadataMaxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > metadataMaxBytes {
		return nil, 0, fmt.Errorf("%w: larger than %d bytes", errMetadata, metadataMaxBytes)
	}
	var doc metadataDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errMetadata, err)
	}
	c, err := f.p.metadataToClient(rawURL, &doc)
	if err != nil {
		return nil, 0, err
	}
	return c, cacheAge(res.Header.Get("Cache-Control")), nil
}

// metadataToClient checks a document as dynamic registration checks its metadata, and turns it
// into a public dynamic client.
func (p *Provider) metadataToClient(rawURL string, doc *metadataDoc) (*authx.OAuthClient, error) {
	if doc.ClientID != rawURL {
		return nil, fmt.Errorf("%w: client_id %q is not the document's URL", errMetadata, doc.ClientID)
	}
	if doc.ClientSecret != "" {
		return nil, fmt.Errorf("%w: a document must not carry a client_secret", errMetadata)
	}
	if len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > 10 {
		return nil, fmt.Errorf("%w: one to ten redirect_uris are required", errMetadata)
	}
	for _, u := range doc.RedirectURIs {
		if !p.redirectOK(u) {
			return nil, fmt.Errorf("%w: redirect_uri %q is not allowed", errMetadata, u)
		}
	}
	switch doc.TokenEndpointAuthMethod {
	case "", string(oidc.AuthMethodNone):
	default: // private_key_jwt is allowed by the spec, but not supported here
		return nil, fmt.Errorf("%w: token_endpoint_auth_method %q is not supported (only none)", errMetadata, doc.TokenEndpointAuthMethod)
	}
	if len(doc.ResponseTypes) > 0 && !slices.Equal(doc.ResponseTypes, []string{string(oidc.ResponseTypeCode)}) {
		return nil, fmt.Errorf("%w: only the code response type is supported", errMetadata)
	}
	grants := slices.Clone(doc.GrantTypes)
	for _, g := range grants {
		if g != string(oidc.GrantTypeCode) && g != string(oidc.GrantTypeRefreshToken) {
			return nil, fmt.Errorf("%w: grant type %q is not supported", errMetadata, g)
		}
	}
	if !slices.Contains(grants, string(oidc.GrantTypeCode)) {
		grants = append(grants, string(oidc.GrantTypeCode))
	}
	return &authx.OAuthClient{
		ID: rawURL, Name: cleanName(doc.ClientName), URI: httpsOrEmpty(doc.ClientURI), LogoURI: httpsOrEmpty(doc.LogoURI),
		RedirectURIs: slices.Clone(doc.RedirectURIs), GrantTypes: grants, AuthMethod: string(oidc.AuthMethodNone),
		Dynamic: true, CreatedAt: p.now().UTC(),
	}, nil
}

// cacheAge is how long to keep a document: its Cache-Control max-age, held within
// [metadataMinAge, metadataMaxAge] (no-store and no-cache get the minimum), else metadataDefAge.
func cacheAge(cc string) time.Duration {
	age := metadataDefAge
	for _, d := range strings.Split(cc, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(d), "=")
		switch strings.ToLower(k) {
		case "no-store", "no-cache":
			return metadataMinAge
		case "max-age":
			if n, err := strconv.ParseInt(strings.Trim(v, `"`), 10, 64); err == nil && n >= 0 {
				age = time.Duration(min(n, int64(metadataMaxAge/time.Second))) * time.Second
			}
		}
	}
	return min(max(age, metadataMinAge), metadataMaxAge)
}
