package oidcprovider_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authx "github.com/alex-savin/go-auth-x"
	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// docServer serves client metadata documents over TLS, counting the fetches per path.
type docServer struct {
	srv  *httptest.Server
	hits map[string]*atomic.Int32
}

func newDocServer(t *testing.T) *docServer {
	d := &docServer{hits: map[string]*atomic.Int32{}}
	mux := http.NewServeMux()
	d.srv = httptest.NewTLSServer(mux)
	t.Cleanup(d.srv.Close)
	doc := func(path string, mod func(m map[string]any)) {
		d.hits[path] = &atomic.Int32{}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			d.hits[path].Add(1)
			m := map[string]any{
				"client_id": d.srv.URL + path, "client_name": "Doc Client", "client_uri": "https://client.example",
				"logo_uri": "https://client.example/logo.png", "redirect_uris": []string{redirect},
				"grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=600")
			if mod != nil {
				mod(m)
			}
			if ct, ok := m["_content_type"].(string); ok {
				w.Header().Set("Content-Type", ct)
				delete(m, "_content_type")
			}
			_ = json.NewEncoder(w).Encode(m)
		})
	}
	doc("/client.json", nil)
	doc("/mismatch.json", func(m map[string]any) { m["client_id"] = d.srv.URL + "/other.json" })
	doc("/big.json", func(m map[string]any) { m["pad"] = strings.Repeat("x", 70<<10) })
	doc("/text.json", func(m map[string]any) { m["_content_type"] = "text/html" })
	doc("/jwt.json", func(m map[string]any) { m["token_endpoint_auth_method"] = "private_key_jwt" })
	doc("/secret.json", func(m map[string]any) { m["client_secret"] = "s3cret" })
	doc("/evil-redirect.json", func(m map[string]any) { m["redirect_uris"] = []string{"http://evil.example/cb"} })
	mux.HandleFunc("/moved.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+strings.TrimPrefix(d.srv.URL, "https://")+"/client.json", http.StatusFound)
	})
	return d
}

func (d *docServer) url(path string) string { return d.srv.URL + path }

// refused reports whether /authorize turned the client away (no login step).
func (h *harness) refused(clientID string) bool {
	h.t.Helper()
	_, ch := pkce()
	res := h.get(h.web, "/oauth/authorize?"+url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"state": {"s"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}.Encode())
	return !strings.Contains(res.Header.Get("Location"), "/oauth/login")
}

func TestClientMetadataDocument(t *testing.T) {
	h := setup(t, func(c *oidcprovider.Config) { c.ClientMetadataDocuments = true })
	clk := newClock()
	oidcprovider.SetClock(h.p, clk.Now)
	docs := newDocServer(t)
	pool := docs.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	oidcprovider.UseTestMetadataServer(h.p, pool)
	ctx := context.Background()

	res, err := http.Get(h.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	_ = json.NewDecoder(res.Body).Decode(&meta)
	res.Body.Close()
	if meta["client_id_metadata_document_supported"] != true {
		t.Fatalf("metadata must advertise client_id_metadata_document_supported: %v", meta)
	}

	// The full flow with a URL client_id, never registered.
	cid := docs.url("/client.json")
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	id := h.authorize(cid, nil)
	req, err := h.p.Pending(ctx, id, h.user.Sub)
	if err != nil {
		t.Fatal(err)
	}
	if c := req.Client; c.ID != cid || c.Name != "Doc Client" || c.URI != "https://client.example" ||
		c.LogoURI != "https://client.example/logo.png" || !c.Dynamic || c.RedirectHost != "127.0.0.1:9999" {
		t.Fatalf("pending client = %+v", c)
	}
	next, err := h.p.Approve(ctx, id, h.user.Sub, oidcprovider.Decision{Scopes: []string{"tree:read"}})
	if err != nil {
		t.Fatal(err)
	}
	st, tok := h.exchange(cid, h.code(next))
	if st != 200 || tok["access_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token = %d %v", st, tok)
	}
	g, err := h.p.Verify(ctx, tok["access_token"].(string))
	if err != nil || g.ClientID != cid || g.ClientName != "Doc Client" {
		t.Fatalf("verify = %+v %v", g, err)
	}
	st, tok = h.post("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {cid}})
	if st != 200 {
		t.Fatalf("refresh = %d %v", st, tok)
	}
	if _, err := h.store.OAuthClient(cid); !errors.Is(err, authx.ErrOAuthNotFound) {
		t.Fatalf("a metadata-document client must not be stored: %v", err)
	}

	// Cached: fetched once for the whole flow, again once its max-age (600 s) has passed.
	if n := docs.hits["/client.json"].Load(); n != 1 {
		t.Fatalf("the document was fetched %d times, want 1", n)
	}
	clk.Add(9 * time.Minute)
	h.authorize(cid, nil)
	if n := docs.hits["/client.json"].Load(); n != 1 {
		t.Fatalf("within max-age the cache must answer, fetched %d times", n)
	}
	clk.Add(2 * time.Minute)
	h.authorize(cid, nil)
	if n := docs.hits["/client.json"].Load(); n != 2 {
		t.Fatalf("after max-age the document must be fetched again, fetched %d times", n)
	}

	// Refused documents.
	for _, path := range []string{"/mismatch.json", "/big.json", "/text.json", "/jwt.json", "/secret.json", "/evil-redirect.json", "/moved.json", "/missing.json"} {
		if !h.refused(docs.url(path)) {
			t.Errorf("%s must be refused", path)
		}
	}
	// Not https: an ordinary (unknown) client id, never fetched.
	if !h.refused("http://" + strings.TrimPrefix(docs.url("/client.json"), "https://")) {
		t.Error("an http client_id must be refused")
	}
	if n := docs.hits["/client.json"].Load(); n != 2 {
		t.Fatalf("an http client_id must not be fetched (%d fetches)", n)
	}
}

func TestClientMetadataDocumentOff(t *testing.T) {
	h := setup(t)
	docs := newDocServer(t)
	oidcprovider.UseTestMetadataServer(h.p, docs.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	h.signIn(h.web, "u@x.com", "correct horse battery staple")
	if !h.refused(docs.url("/client.json")) {
		t.Fatal("a URL client_id must be refused when ClientMetadataDocuments is off")
	}
	if n := docs.hits["/client.json"].Load(); n != 0 {
		t.Fatalf("nothing may be fetched when it is off (%d fetches)", n)
	}
	res, err := http.Get(h.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var meta map[string]any
	_ = json.NewDecoder(res.Body).Decode(&meta)
	if _, ok := meta["client_id_metadata_document_supported"]; ok {
		t.Fatal("metadata must not advertise client metadata documents when off")
	}
}
