package oidcprovider

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	authx "github.com/alex-savin/go-auth-x"
)

// registration is the RFC 7591 client metadata a client sends (and gets back).
type registration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// register is dynamic client registration (RFC 7591). Anyone may register — registering gives
// no access, only a user's approval does — so it is limited per address, and a client that never
// gets a token is removed after Config.UnusedClientTTL.
func (p *Provider) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !p.reg.allow(p.cfg.Auth.ClientIP(r), time.Now()) {
		writeErr(w, http.StatusTooManyRequests, "too_many_requests", "too many registrations; try again later")
		return
	}
	var m registration
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&m); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_client_metadata", "the body must be JSON client metadata")
		return
	}
	if len(m.RedirectURIs) == 0 || len(m.RedirectURIs) > 10 {
		writeErr(w, http.StatusBadRequest, "invalid_redirect_uri", "one to ten redirect_uris are required")
		return
	}
	for _, u := range m.RedirectURIs {
		if !p.redirectOK(u) {
			writeErr(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be https, a loopback http address, or an app's own scheme")
			return
		}
	}
	if len(m.ResponseTypes) == 0 {
		m.ResponseTypes = []string{string(oidc.ResponseTypeCode)}
	}
	if !slices.Equal(m.ResponseTypes, []string{string(oidc.ResponseTypeCode)}) {
		writeErr(w, http.StatusBadRequest, "invalid_client_metadata", "only the code response type is supported")
		return
	}
	if len(m.GrantTypes) == 0 {
		m.GrantTypes = []string{string(oidc.GrantTypeCode)}
	}
	for _, g := range m.GrantTypes {
		if g != string(oidc.GrantTypeCode) && g != string(oidc.GrantTypeRefreshToken) {
			writeErr(w, http.StatusBadRequest, "invalid_client_metadata", "grant_types may be authorization_code and refresh_token")
			return
		}
	}
	if !slices.Contains(m.GrantTypes, string(oidc.GrantTypeCode)) {
		m.GrantTypes = append(m.GrantTypes, string(oidc.GrantTypeCode))
	}
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = string(oidc.AuthMethodBasic) // RFC 7591's default
	}
	switch oidc.AuthMethod(m.TokenEndpointAuthMethod) {
	case oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost:
	default:
		writeErr(w, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method may be none, client_secret_basic or client_secret_post")
		return
	}
	m.ClientName = cleanName(m.ClientName)
	m.ClientURI = httpsOrEmpty(m.ClientURI)
	m.LogoURI = httpsOrEmpty(m.LogoURI)
	m.Scope = ""

	now := time.Now().UTC()
	c := &authx.OAuthClient{
		ID: "dyn_" + randomID(16), Name: m.ClientName, URI: m.ClientURI, LogoURI: m.LogoURI,
		RedirectURIs: m.RedirectURIs, GrantTypes: m.GrantTypes, AuthMethod: m.TokenEndpointAuthMethod, Dynamic: true, CreatedAt: now,
	}
	secret := ""
	if c.AuthMethod != string(oidc.AuthMethodNone) {
		secret = randomID(32)
		c.SecretHash = hash(secret)
	}
	if err := p.cfg.Store.CreateOAuthClient(c); err != nil {
		p.cfg.Logger.Error("oidcprovider: registering a client failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	out := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        now.Unix(),
		"redirect_uris":              m.RedirectURIs,
		"grant_types":                m.GrantTypes,
		"response_types":             m.ResponseTypes,
		"token_endpoint_auth_method": m.TokenEndpointAuthMethod,
	}
	if secret != "" {
		out["client_secret"] = secret
		out["client_secret_expires_at"] = 0
	}
	for k, v := range map[string]string{"client_name": m.ClientName, "client_uri": m.ClientURI, "logo_uri": m.LogoURI} {
		if v != "" {
			out[k] = v
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

// RegisterClient adds a client the app knows (not dynamic). A confidential client gets a secret,
// returned once; a public one (AuthMethod "none") must use PKCE.
func (p *Provider) RegisterClient(c authx.OAuthClient) (secret string, err error) {
	if c.ID == "" {
		c.ID = randomID(16)
	}
	if c.AuthMethod == "" {
		c.AuthMethod = string(oidc.AuthMethodBasic)
	}
	if len(c.GrantTypes) == 0 {
		c.GrantTypes = []string{string(oidc.GrantTypeCode), string(oidc.GrantTypeRefreshToken)}
	}
	if c.AuthMethod != string(oidc.AuthMethodNone) {
		secret = randomID(32)
		c.SecretHash = hash(secret)
	}
	c.Dynamic = false
	c.CreatedAt = time.Now().UTC()
	return secret, p.cfg.Store.CreateOAuthClient(&c)
}

// redirectOK allows https, http to a loopback address (a native app's local listener), and a
// private-use scheme in reverse-domain form ("com.example.app:/cb", RFC 8252) — never javascript:,
// data: or the like, and no fragments.
func (p *Provider) redirectOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Scheme == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return strings.Contains(u.Scheme, ".")
}

func httpsOrEmpty(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || len(raw) > 500 {
		return ""
	}
	return u.String()
}

// cleanName keeps a client's self-chosen name printable and short (it is shown to the user).
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}

// discovery serves the metadata at /.well-known/openid-configuration and RFC 8414's
// /.well-known/oauth-authorization-server: zitadel's document, plus the registration endpoint,
// public clients and the response iss parameter.
func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/.well-known/openid-configuration"
	p.op.ServeHTTP(rec, r2)
	var doc map[string]any
	if rec.Code != http.StatusOK || json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&doc) != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if p.cfg.Registration {
		doc["registration_endpoint"] = p.cfg.Issuer + p.prefix + "/register"
	}
	doc["code_challenge_methods_supported"] = []string{string(oidc.CodeChallengeMethodS256)}
	doc["response_types_supported"] = []string{string(oidc.ResponseTypeCode)}
	doc["grant_types_supported"] = []string{string(oidc.GrantTypeCode), string(oidc.GrantTypeRefreshToken)}
	delete(doc, "device_authorization_endpoint")
	w.Header().Set("Access-Control-Allow-Origin", "*") // browser-based clients read it cross-origin
	writeJSON(w, http.StatusOK, doc)
}
