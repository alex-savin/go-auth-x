package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	authx "github.com/alex-savin/go-auth-x"
)

// Errors of the consent and verification API.
var (
	// ErrNoRequest: the authorization request is unknown, expired, or someone else's.
	ErrNoRequest = errors.New("oidcprovider: no such authorization request")
	// ErrInvalidToken: the access token is malformed, unknown, expired or revoked.
	ErrInvalidToken = errors.New("oidcprovider: invalid access token")
)

// authorize checks the resource indicators and fills in default scopes, then hands the request
// to zitadel, which validates the client, redirect and PKCE and sends the browser to login.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, ok := p.resources(r.Form["resource"])
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid_target", "this resource is not served here")
		return
	}
	if strings.TrimSpace(r.Form.Get("scope")) == "" && len(p.cfg.DefaultScopes) > 0 {
		q := r.URL.Query()
		q.Set("scope", strings.Join(p.cfg.DefaultScopes, " "))
		r.URL.RawQuery = q.Encode()
		if r.Method == http.MethodPost {
			r.PostForm.Set("scope", strings.Join(p.cfg.DefaultScopes, " "))
		}
		r.Form.Set("scope", strings.Join(p.cfg.DefaultScopes, " "))
	}
	p.op.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resourcesKey, res)))
}

// login is where zitadel sends the browser with a new request: the user signs in (go-auth-x's own
// login) and comes back, then goes on to the app's consent screen.
func (p *Provider) login(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	req, err := p.store.request(id)
	if err != nil || req.Done {
		http.Error(w, "This sign-in request has expired. Start again from the application.", http.StatusBadRequest)
		return
	}
	sc := p.cfg.Auth.SessionOf(r)
	if sc == nil {
		if slices.Contains(req.Prompt, oidc.PromptNone) {
			p.redirectError(w, r, req, "login_required", "")
			return
		}
		http.Redirect(w, r, p.cfg.LoginURL(p.prefix+"/login?id="+url.QueryEscape(id)), http.StatusFound)
		return
	}
	if _, err := p.cfg.Auth.UserBySub(sc.Subject); err != nil {
		p.redirectError(w, r, req, "access_denied", "this account may not sign in")
		return
	}
	// An admin impersonating a user acts in the app as them for a short, marked session; they don't
	// hand out tokens in the user's name that outlive it, unmarked.
	if sc.ImpersonatedBy != "" {
		p.redirectError(w, r, req, "access_denied", "not while impersonating a user")
		return
	}
	authAt := sessionAuthTime(sc)
	if !freshEnough(req, authAt, time.Now()) {
		// The client wants a fresher sign-in (prompt=login or max_age). Coming back still stale
		// (the app's page sent the signed-in user straight back) ends it rather than looping.
		if slices.Contains(req.Prompt, oidc.PromptNone) || r.URL.Query().Get("reauth") != "" {
			p.redirectError(w, r, req, "login_required", "a fresh sign-in is required")
			return
		}
		http.Redirect(w, r, p.cfg.ReauthURL(p.prefix+"/login?id="+url.QueryEscape(id)+"&reauth=1"), http.StatusFound)
		return
	}
	req.Subject = sc.Subject
	// auth_time is when the user signed in; a session from before the claim existed offers only
	// when its cookie was issued, the closest there is.
	if req.AuthTime = authAt; authAt.IsZero() && sc.IssuedAt != nil {
		req.AuthTime = sc.IssuedAt.Time.UTC()
	}
	if err := p.cfg.Store.SaveOAuthAuthRequest(req); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if p.cfg.ConsentURL == nil {
		// No consent screen: only a client the app registered itself is approved unasked. A client
		// that registered itself (or a metadata document's) could be anyone's, and approving it
		// silently would hand a signed-in user's tokens to whoever sent them the link.
		if c, err := p.client(r.Context(), req.ClientID); err != nil || c.Dynamic {
			p.redirectError(w, r, req, "access_denied", "this client needs the user's consent, and no consent screen is configured")
			return
		}
		to, err := p.Approve(r.Context(), id, sc.Subject, Decision{})
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	if slices.Contains(req.Prompt, oidc.PromptNone) {
		p.redirectError(w, r, req, "consent_required", "")
		return
	}
	http.Redirect(w, r, p.cfg.ConsentURL(id), http.StatusFound)
}

// callback is where an approved request's code is issued and the browser sent back to the client.
// zitadel's handler answers anyone who knows the request's id — and whoever started the request
// knows it. Someone could start one with their own PKCE verifier, have a signed-in user open its
// link and approve what is a genuine client, then fetch the code here themselves, with no session at
// all. So the code is issued only in the browser of the user who signed in for the request, and once.
func (p *Provider) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := p.store.request(r.URL.Query().Get("id"))
	if err != nil || !req.Done || req.Subject == "" {
		p.op.ServeHTTP(w, r) // unknown, expired or not approved: zitadel's answer, which issues nothing
		return
	}
	sc := p.cfg.Auth.SessionOf(r)
	if sc == nil || sc.Subject != req.Subject || sc.ImpersonatedBy != "" {
		http.Error(w, "This sign-in request belongs to another session. Start again from the application.", http.StatusForbidden)
		return
	}
	if req.CodeHash != "" {
		http.Error(w, "This sign-in request was already completed. Start again from the application.", http.StatusBadRequest)
		return
	}
	p.op.ServeHTTP(w, r)
}

// sessionAuthTime is when the session's user signed in, zero when the cookie predates the claim.
func sessionAuthTime(sc *authx.SessionClaims) time.Time {
	if sc.AuthTime == nil {
		return time.Time{}
	}
	return sc.AuthTime.Time.UTC()
}

// freshEnough reports whether a sign-in at authAt satisfies the request's prompt=login (the user
// signed in during this request) and max_age (or, either way, did so since the request began). An
// unknown sign-in time is never fresh enough for a request that asks.
func freshEnough(req *authx.OAuthAuthRequest, authAt, now time.Time) bool {
	login := slices.Contains(req.Prompt, oidc.PromptLogin)
	if !login && req.MaxAge == nil {
		return true
	}
	if authAt.IsZero() {
		return false
	}
	// The session's time has whole seconds; the request's is finer.
	if !authAt.Before(req.CreatedAt.Truncate(time.Second)) {
		return true
	}
	return !login && now.Sub(authAt) <= *req.MaxAge
}

// Request is an authorization request waiting for the user's decision, for the consent screen.
type Request struct {
	ID        string   `json:"id"`
	Client    Client   `json:"client"`
	Scopes    []string `json:"scopes"`    // as asked (offline_access included when it will refresh)
	Resources []string `json:"resources"` // what the tokens will be for
	Subject   string   `json:"subject"`
}

// Client describes a client on the consent screen. Its name, home page and logo were given by
// the client itself when it registered dynamically or in its metadata document (Dynamic; ID is
// then the document's URL): show them as claims, alongside RedirectHost, which is where the
// browser really goes back to.
type Client struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	URI          string `json:"uri,omitempty"`
	LogoURI      string `json:"logoUri,omitempty"`
	RedirectHost string `json:"redirectHost"`
	Dynamic      bool   `json:"dynamic"`
}

// Decision is the user's approval.
type Decision struct {
	// Scopes are those granted: a subset of the request's (nil grants all it asked).
	Scopes []string
	// Ref is the app's own reference for the approval, returned by Verify (e.g. its record of
	// the connection, which it can then revoke with RevokeRef).
	Ref string
	// Expires ends the grant at this time, refresh tokens or not (zero: no end).
	Expires time.Time
}

// Pending returns the request for the consent screen. subject is the signed-in user: a request
// someone else signed in for is ErrNoRequest.
func (p *Provider) Pending(ctx context.Context, id, subject string) (*Request, error) {
	req, err := p.store.request(id)
	if err != nil || req.Done || req.Subject == "" || req.Subject != subject {
		return nil, ErrNoRequest
	}
	c, err := p.client(ctx, req.ClientID)
	if err != nil {
		return nil, ErrNoRequest
	}
	host := req.RedirectURI
	if u, err := url.Parse(req.RedirectURI); err == nil && u.Host != "" {
		host = u.Host
	} else if err == nil {
		host = u.Scheme + ":"
	}
	return &Request{
		ID:        req.ID,
		Client:    Client{ID: c.ID, Name: c.Name, URI: c.URI, LogoURI: c.LogoURI, RedirectHost: host, Dynamic: c.Dynamic},
		Scopes:    slices.Clone(req.Scopes),
		Resources: slices.Clone(req.Resources),
		Subject:   req.Subject,
	}, nil
}

// Approve records the user's approval and returns where to send the browser next (the provider's
// callback, which issues the code to the client).
func (p *Provider) Approve(_ context.Context, id, subject string, d Decision) (string, error) {
	req, err := p.store.request(id)
	if err != nil || req.Done || req.Subject == "" || req.Subject != subject {
		return "", ErrNoRequest
	}
	if d.Scopes != nil {
		var granted []string
		for _, s := range req.Scopes {
			// openid is protocol, not a permission; offline_access (refresh tokens) is the user's to
			// grant like any scope.
			if slices.Contains(d.Scopes, s) || s == oidc.ScopeOpenID {
				granted = append(granted, s)
			}
		}
		req.Scopes = granted
	}
	req.Done = true
	req.Ref = d.Ref
	req.GrantExpiresAt = d.Expires.UTC()
	if d.Expires.IsZero() {
		req.GrantExpiresAt = time.Time{}
	}
	if req.AuthTime.IsZero() { // set by the login step from the session's sign-in
		req.AuthTime = time.Now().UTC()
	}
	if err := p.cfg.Store.SaveOAuthAuthRequest(req); err != nil {
		return "", err
	}
	return p.prefix + "/authorize/callback?id=" + url.QueryEscape(id), nil
}

// Deny records the user's refusal and returns where to send the browser (back to the client,
// with access_denied).
func (p *Provider) Deny(_ context.Context, id, subject string) (string, error) {
	req, err := p.store.request(id)
	if err != nil || req.Done || req.Subject == "" || req.Subject != subject {
		return "", ErrNoRequest
	}
	_ = p.cfg.Store.DeleteOAuthAuthRequest(id)
	return p.errorURL(req, "access_denied", "the user declined")
}

// errorURL is the client's redirect with an error (RFC 6749 §4.1.2.1, with RFC 9207's iss).
func (p *Provider) errorURL(req *authx.OAuthAuthRequest, code, desc string) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}
	v := url.Values{"error": {code}, "iss": {p.cfg.Issuer}}
	if desc != "" {
		v.Set("error_description", desc)
	}
	if req.State != "" {
		v.Set("state", req.State)
	}
	if req.ResponseMode == string(oidc.ResponseModeFragment) {
		u.Fragment = v.Encode()
	} else {
		q := u.Query()
		for k, vs := range v {
			q[k] = vs
		}
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

func (p *Provider) redirectError(w http.ResponseWriter, r *http.Request, req *authx.OAuthAuthRequest, code, desc string) {
	_ = p.cfg.Store.DeleteOAuthAuthRequest(req.ID)
	to, err := p.errorURL(req, code, desc)
	if err != nil {
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, to, http.StatusFound)
}

// consentJSON is the consent decision as JSON endpoints, for an app that renders its consent
// screen from them without code of its own: GET ?id= returns the Request; POST {id, approve,
// scopes} records the decision and returns {redirect}. Both need the user's session; POST also
// the CSRF token. An app that needs its own reference or end date calls Approve itself.
func (p *Provider) consentJSON(w http.ResponseWriter, r *http.Request) {
	sc := p.cfg.Auth.SessionOf(r)
	if sc == nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "")
		return
	}
	switch r.Method {
	case http.MethodGet:
		req, err := p.Pending(r.Context(), r.URL.Query().Get("id"), sc.Subject)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not_found", "")
			return
		}
		writeJSON(w, http.StatusOK, req)
	case http.MethodPost:
		if !p.cfg.Auth.CSRFValid(r) {
			writeErr(w, http.StatusForbidden, "csrf", "invalid or missing CSRF token")
			return
		}
		var body struct {
			ID      string   `json:"id"`
			Approve bool     `json:"approve"`
			Scopes  []string `json:"scopes"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "")
			return
		}
		var to string
		var err error
		if body.Approve {
			to, err = p.Approve(r.Context(), body.ID, sc.Subject, Decision{Scopes: body.Scopes})
		} else {
			to, err = p.Deny(r.Context(), body.ID, sc.Subject)
		}
		if err != nil {
			writeErr(w, http.StatusNotFound, "not_found", "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"redirect": to})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Grant is what a verified access token allows.
type Grant struct {
	ID         string
	ClientID   string
	ClientName string
	Subject    string
	Scopes     []string
	Resources  []string
	Ref        string
	ExpiresAt  time.Time // the access token's expiry
}

// Verify checks an access token: issued here, not expired, its grant neither revoked nor past its
// end, and its user still allowed to sign in (a disabled, banned or deleted user's tokens stop at
// once, not when they expire). A caller serving a resource must also check that Resources
// includes it (VerifyFor does).
func (p *Provider) Verify(_ context.Context, token string) (*Grant, error) {
	plain, err := p.op.Crypto().Decrypt(token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	id, sub, ok := strings.Cut(plain, ":")
	if !ok {
		return nil, ErrInvalidToken
	}
	sub = unescapeSubject(sub)
	t, g, err := p.store.liveToken(id, sub)
	if err != nil {
		return nil, ErrInvalidToken
	}
	name := ""
	if p.metadataClient(t.ClientID) {
		// Not fetched here (Verify is on every request): the name if the document is cached.
		if c := p.cimd.cached(t.ClientID); c != nil {
			name = c.Name
		}
	} else if c, err := p.cfg.Store.OAuthClient(t.ClientID); err == nil {
		name = c.Name
	}
	return &Grant{ID: g.ID, ClientID: t.ClientID, ClientName: name, Subject: sub, Scopes: slices.Clone(t.Scopes),
		Resources: slices.Clone(g.Resources), Ref: g.Ref, ExpiresAt: t.ExpiresAt}, nil
}

// VerifyFor is Verify for a token that must be bound to resource.
func (p *Provider) VerifyFor(ctx context.Context, token, resource string) (*Grant, error) {
	g, err := p.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(g.Resources, normResource(resource)) {
		return nil, ErrInvalidToken
	}
	return g, nil
}

// RevokeRef ends every grant made with this reference (the app revoked its connection).
func (p *Provider) RevokeRef(_ context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	_, err := p.cfg.Store.RevokeOAuthGrants(authx.OAuthGrantFilter{Ref: ref}, time.Now().UTC())
	return err
}

// RevokeUser ends every grant of the user with this subject — e.g. "disconnect all apps", or on
// deleting the account with a store that doesn't remove OAuth records itself (both reference stores
// do); the clean-up then deletes them.
func (p *Provider) RevokeUser(_ context.Context, subject string) error {
	if subject == "" {
		return nil
	}
	_, err := p.cfg.Store.RevokeOAuthGrants(authx.OAuthGrantFilter{Subject: subject}, time.Now().UTC())
	return err
}

// RevokeGrant ends one grant.
func (p *Provider) RevokeGrant(_ context.Context, id string) error {
	if id == "" {
		return nil
	}
	_, err := p.cfg.Store.RevokeOAuthGrants(authx.OAuthGrantFilter{ID: id}, time.Now().UTC())
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, e, desc string) {
	body := map[string]string{"error": e}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, code, body)
}

var _ = op.AuthCallbackURL // the callback path ("/authorize/callback") is zitadel's
