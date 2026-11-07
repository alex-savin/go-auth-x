package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestPublicAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"93.184.216.34", true},
		{"2606:4700:4700::1111", true},
		{"2a00:1450:4001:80b::200e", true},
		{"::ffff:8.8.8.8", true},

		{"127.0.0.1", false},        // loopback
		{"127.10.0.1", false},       // loopback
		{"::1", false},              // loopback
		{"::ffff:127.0.0.1", false}, // loopback, IPv4-mapped
		{"10.0.0.1", false},         // private
		{"172.16.5.4", false},       // private
		{"192.168.1.1", false},      // private
		{"::ffff:192.168.1.1", false},
		{"::ffff:10.1.2.3", false},
		{"fc00::1", false},         // unique local
		{"fd12:3456::1", false},    // unique local
		{"169.254.169.254", false}, // link-local (cloud metadata)
		{"::ffff:169.254.169.254", false},
		{"fe80::1", false},             // link-local
		{"fe80::1%en0", false},         // zoned
		{"100.64.0.1", false},          // CGNAT
		{"100.127.255.254", false},     // CGNAT
		{"0.0.0.0", false},             // unspecified
		{"::", false},                  // unspecified
		{"0.1.2.3", false},             // "this network"
		{"224.0.0.1", false},           // multicast
		{"239.255.255.250", false},     // multicast
		{"ff02::1", false},             // multicast
		{"ff05::2", false},             // multicast
		{"255.255.255.255", false},     // broadcast
		{"240.0.0.1", false},           // reserved
		{"192.0.2.1", false},           // documentation
		{"198.18.0.1", false},          // benchmarking
		{"2001:db8::1", false},         // documentation
		{"64:ff9b::a00:1", false},      // NAT64 of 10.0.0.1
		{"2002:a00:1::1", false},       // 6to4 of 10.0.0.1
		{"2001:0:4136:e378::1", false}, // Teredo
		{"::7f00:1", false},            // IPv4-compatible 127.0.0.1
		{"fec0::1", false},             // site-local
	} {
		a, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("%s: %v", tc.addr, err)
		}
		if got := publicAddr(a); got != tc.ok {
			t.Errorf("publicAddr(%s) = %v, want %v", tc.addr, got, tc.ok)
		}
	}
	if publicAddr(netip.Addr{}) {
		t.Error("the zero address must not be public")
	}
}

func TestIsMetadataURL(t *testing.T) {
	for _, tc := range []struct {
		id string
		ok bool
	}{
		{"https://client.example/meta.json", true},
		{"https://client.example:8443/a/b?x=1", true},
		{"https://client.example", false},
		{"https://client.example/", false},
		{"http://client.example/meta.json", false},
		{"https://user:pw@client.example/meta.json", false},
		{"https://client.example/meta.json#x", false},
		{"https://client.example/a/../meta.json", false},
		{"https://client.example/./meta.json", false},
		{"dyn_abc", false},
		{"", false},
	} {
		if got := isMetadataURL(tc.id); got != tc.ok {
			t.Errorf("isMetadataURL(%q) = %v, want %v", tc.id, got, tc.ok)
		}
	}
}

func TestCacheAge(t *testing.T) {
	for _, tc := range []struct {
		cc   string
		want time.Duration
	}{
		{"", time.Hour},
		{"public", time.Hour},
		{"max-age=600", 10 * time.Minute},
		{"public, max-age=7200", 2 * time.Hour},
		{"max-age=10", 5 * time.Minute},
		{"max-age=0", 5 * time.Minute},
		{"max-age=999999999999", 24 * time.Hour},
		{"no-store", 5 * time.Minute},
		{"no-cache, max-age=3600", 5 * time.Minute},
		{"max-age=bogus", time.Hour},
	} {
		if got := cacheAge(tc.cc); got != tc.want {
			t.Errorf("cacheAge(%q) = %v, want %v", tc.cc, got, tc.want)
		}
	}
}

// Without the test allowance, the fetcher refuses a server on a loopback address, by literal or
// by name, before anything is sent.
func TestMetadataFetchRefusesLoopback(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	p := &Provider{now: time.Now, cfg: Config{Logger: slog.New(slog.DiscardHandler)}}
	f := newMetadataFetcher(p, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, false)
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	for _, u := range []string{srv.URL + "/c.json", "https://localhost" + port + "/c.json"} {
		_, _, err := f.fetch(context.Background(), u)
		if !errors.Is(err, errMetadata) || !strings.Contains(err.Error(), "not public") {
			t.Errorf("fetch %s = %v, want a refusal", u, err)
		}
	}
	if hit {
		t.Fatal("the loopback server must never be reached")
	}
}

// The cache stays bounded.
func TestMetadataCacheBounded(t *testing.T) {
	p := &Provider{now: time.Now, cfg: Config{Logger: slog.New(slog.DiscardHandler)}}
	f := newMetadataFetcher(p, nil, false)
	now := time.Now()
	for i := range metadataCacheMax + 50 {
		f.put("https://c.example/"+string(rune('a'+i%26))+strings.Repeat("x", i), metadataEntry{exp: now.Add(time.Duration(i) * time.Second)}, now)
	}
	if n := len(f.cache); n > metadataCacheMax {
		t.Fatalf("cache holds %d entries, more than %d", n, metadataCacheMax)
	}
}

// subjectCrypto escapes a decrypted access token's subject so zitadel's "id:subject" split sees
// two parts, and unescapeSubject restores it exactly — colons and percent signs included.
func TestSubjectCryptoRoundTrip(t *testing.T) {
	var key [32]byte
	c := subjectCrypto{op.NewAES256GCMCrypto(key, "")}
	for _, sub := range []string{"local:abc", "scim:org7:jdoe", "plain", "odd%3A:%25:%"} {
		enc, err := c.Encrypt("tok123:" + sub)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := c.Decrypt(enc)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(dec, ":")
		if len(parts) != 2 || parts[0] != "tok123" || unescapeSubject(parts[1]) != sub {
			t.Errorf("%q decrypted to %q", sub, dec)
		}
	}
	if enc, _ := c.Encrypt("requestid"); func() string { d, _ := c.Decrypt(enc); return d }() != "requestid" {
		t.Error("a value without a colon must decrypt unchanged")
	}
}

// Fetches the cache can't answer are limited per address; being over the limit isn't cached against
// the document (another address still fetches it), and cached answers don't count.
func TestMetadataFetchLimit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	p := &Provider{now: time.Now, cfg: Config{Logger: slog.New(slog.DiscardHandler)}}
	f := newMetadataFetcher(p, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, true)
	from := func(key string) context.Context { return context.WithValue(context.Background(), clientKey, key) }

	for i := range metadataFetches {
		if _, err := f.get(from("a"), fmt.Sprintf("%s/c%d.json", srv.URL, i)); errors.Is(err, errMetadataBusy) {
			t.Fatalf("fetch %d refused as over the limit", i)
		}
	}
	if _, err := f.get(from("a"), srv.URL+"/one-more.json"); !errors.Is(err, errMetadataBusy) {
		t.Fatalf("a fetch past the limit = %v, want errMetadataBusy", err)
	}
	if n := hits.Load(); n != metadataFetches {
		t.Fatalf("the server saw %d fetches, want %d", n, metadataFetches)
	}
	if _, err := f.get(from("b"), srv.URL+"/one-more.json"); errors.Is(err, errMetadataBusy) || !errors.Is(err, errMetadata) {
		t.Fatalf("another address must fetch the document, got %v", err)
	}
	if _, err := f.get(from("a"), srv.URL+"/c0.json"); errors.Is(err, errMetadataBusy) {
		t.Fatal("a cached answer must not count against the limit")
	}
	if n := hits.Load(); n != metadataFetches+1 {
		t.Fatalf("the server saw %d fetches, want %d", n, metadataFetches+1)
	}
}

// Concurrent lookups of one document share a single fetch.
func TestMetadataFetchShared(t *testing.T) {
	var hits atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		http.NotFound(w, r)
	}))
	defer srv.Close()
	defer unblock() // runs first: a failing test must not leave handlers blocking srv.Close
	p := &Provider{now: time.Now, cfg: Config{Logger: slog.New(slog.DiscardHandler)}}
	f := newMetadataFetcher(p, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, true)

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.get(context.Background(), srv.URL+"/c.json")
		}()
	}
	for hits.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // the others arrive and wait on the fetch under way
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d fetches under way, want 1", n)
	}
	unblock()
	wg.Wait()
	if n := hits.Load(); n != 1 {
		t.Fatalf("the document was fetched %d times, want once", n)
	}
}
