package oidcprovider_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alex-savin/go-auth-x/oidcprovider"
)

// TestCIMDRefusesRedirects checks that a client metadata document is only accepted when it is
// served at the client_id URL itself. draft-ietf-oauth-client-id-metadata-document says the AS
// MUST NOT follow redirects, and the client_id must match the URL the document was fetched from.
// Here origin A redirects to origin B, and B serves a document whose client_id is A's URL.
func TestCIMDRefusesRedirects(t *testing.T) {
	h := setup(t, func(c *oidcprovider.Config) { c.ClientMetadataDocuments = true })

	// Origin B: serves a document naming a client_id on origin A.
	var aURL string
	b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id": aURL + "/go", "client_name": "Doc Client", "redirect_uris": []string{redirect},
			"grant_types": []string{"authorization_code"}, "token_endpoint_auth_method": "none",
		})
	}))
	t.Cleanup(b.Close)
	// Origin A: redirects /go to origin B.
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/doc.json", http.StatusFound)
	}))
	t.Cleanup(a.Close)
	aURL = a.URL

	// httptest TLS servers share one test certificate, so one pool trusts both.
	pool := a.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	oidcprovider.UseTestMetadataServer(h.p, pool)

	if !h.refused(aURL + "/go") {
		t.Fatalf("a document served by %s after a redirect was accepted for client_id %s/go", b.URL, aURL)
	}
}
