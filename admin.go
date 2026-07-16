package authx

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

// --- access control: groups (the per-group analog of an IdP's per-client access, for a BFF) ---

// RequireGroupsHTTP is net/http middleware permitting only principals (a session user gated by
// GateHTTP, OR a valid API key) in at least one of the named groups. Empty names = any AUTHENTICATED
// principal (a session or a valid key) — NOT anonymous access; an unauthenticated request is refused.
func (a *Authenticator) RequireGroupsHTTP(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(groups) == 0 {
				if !a.authenticated(r) {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: authentication required"})
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if !hasAnyGroup(a.requestGroups(r), groups) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: requires group membership"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// authenticated reports whether the request carries a GLOBAL principal: a session attached by
// GateHTTP, or a valid GLOBAL API-key Bearer token. An org-bound key is not a global principal (it
// authorizes only its org's surfaces), so it does NOT satisfy an empty-groups RequireGroupsHTTP.
func (a *Authenticator) authenticated(r *http.Request) bool {
	if _, _, ok := SessionFromRequest(r); ok {
		return true
	}
	if key := bearerToken(r.Header.Get("Authorization")); key != "" {
		if info, ok := a.ValidateAPIKey(key); ok {
			return info.OrgID == ""
		}
	}
	return false
}

// GroupsFromRequest returns the groups of the session attached by GateHTTP.
func GroupsFromRequest(r *http.Request) []string {
	if sc, ok := r.Context().Value(sessionCtxKey).(*SessionClaims); ok && sc != nil {
		return sc.Groups
	}
	return nil
}

// requestGroups returns the groups of whichever principal authenticated the request — the gated
// session user, plus a GLOBAL API key's groups if a valid Bearer key is present. An org-bound
// key's groups never merge: group gates are global surfaces, outside an org key's blast radius.
func (a *Authenticator) requestGroups(r *http.Request) []string {
	have := GroupsFromRequest(r)
	if key := bearerToken(r.Header.Get("Authorization")); key != "" {
		if info, ok := a.ValidateAPIKey(key); ok && info.OrgID == "" {
			have = append(have, info.Groups...)
		}
	}
	return have
}

// --- API keys ---

const apiKeyPrefix = "axk_"

// generateAPIKey returns (raw, prefix, hash). The raw key is shown ONCE; only the hash is stored.
func generateAPIKey() (raw, prefix string, hash []byte) {
	raw = apiKeyPrefix + randToken()
	prefix = raw
	if len(raw) > 12 {
		prefix = raw[:12]
	}
	return raw, prefix, hashToken(raw)
}

// ValidateAPIKey resolves a raw API key to its info if it exists and is not expired (and stamps
// last-used). Useful for wiring API-key auth into other surfaces (e.g. the SCIM server).
func (a *Authenticator) ValidateAPIKey(raw string) (*APIKeyInfo, bool) {
	if a.dir == nil || raw == "" {
		return nil, false
	}
	info, err := a.dir.APIKeyByHash(hashToken(raw))
	if err != nil || (info.ExpiresAt != nil && time.Now().After(*info.ExpiresAt)) {
		return nil, false
	}
	_ = a.dir.TouchAPIKey(info.ID)
	return info, true
}

// ValidateAPIKeyScope is ValidateAPIKey plus a scope check — convenient for gating a GLOBAL
// surface (e.g. the global SCIM server) to keys that carry a specific scope:
//
//	scim.NewServer(store, func(t string) bool { return authn.ValidateAPIKeyScope(t, "scim") })
//
// Org-bound keys (OrgID != "") are REFUSED here — a key bound to one org grants nothing outside
// it; gate per-org surfaces with ValidateOrgAPIKeyScope instead.
func (a *Authenticator) ValidateAPIKeyScope(raw, scope string) bool {
	info, ok := a.ValidateAPIKey(raw)
	return ok && KeyHasScope(info, scope) && info.OrgID == ""
}

func bearerToken(h string) string {
	const p = "Bearer "
	if strings.HasPrefix(h, p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

// --- admin REST API ---

// adminGuard permits the instance owner (OWNER_EMAIL session, resolved from the cookie) or a valid
// API key carrying the 'admin' scope. The owner mints the first admin key via an owner session.
func (a *Authenticator) adminGuard(c *reqCtx) bool {
	// An admin-scoped API key OR an owner session grants access. Check BOTH before failing, so a valid
	// owner session isn't rejected merely because a stray/invalid Bearer header is also present.
	keyPresent, keyValidNoScope := false, false
	if key := bearerToken(c.GetHeader("Authorization")); key != "" {
		keyPresent = true
		if info, ok := a.ValidateAPIKey(key); ok {
			// An ORG-BOUND key never grants GLOBAL admin, whatever scopes it carries — its blast
			// radius is its org (ValidateOrgAPIKeyScope). Only a global key passes here.
			if KeyHasScope(info, "admin") && info.OrgID == "" {
				return true
			}
			keyValidNoScope = true
		}
	}
	// An impersonation session must NOT be able to act as admin (it carries ImpersonatedBy), even if
	// the impersonated user happens to be the owner.
	if sc := a.sessionOf(c); sc != nil && sc.ImpersonatedBy == "" && a.cfg.OwnerEmail != "" &&
		strings.EqualFold(strings.TrimSpace(sc.Email), a.cfg.OwnerEmail) {
		return true
	}
	switch {
	case keyValidNoScope:
		// A valid key that merely lacks the scope is 403 insufficient_scope (RFC 6750 §3.1).
		c.JSON(http.StatusForbidden, H{"error": "insufficient_scope: the 'admin' scope is required"})
	case keyPresent:
		// RFC 6750 §3.1: an invalid/expired token is 401 invalid_token with a challenge.
		c.w.Header().Set("WWW-Authenticate", `Bearer realm="auth", error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, H{"error": "API key is invalid or expired"})
	default:
		// No credentials presented → challenge for a Bearer token (RFC 6750 §3).
		c.w.Header().Set("WWW-Authenticate", `Bearer realm="auth"`)
		c.JSON(http.StatusUnauthorized, H{"error": "owner session or API key with 'admin' scope required"})
	}
	return false
}

// adminRoutes mounts the admin REST API under /auth/admin (called by routes() when a directory
// store is wired). Each handler self-gates via adminGuard.
func (a *Authenticator) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/admin/groups", a.wrap(a.adminListGroups))
	mux.HandleFunc("POST /auth/admin/groups", a.wrap(a.adminCreateGroup))
	mux.HandleFunc("DELETE /auth/admin/groups/{id}", a.wrap(a.adminDeleteGroup))
	mux.HandleFunc("POST /auth/admin/groups/{id}/members/{userId}", a.wrap(a.adminAddMember))
	mux.HandleFunc("DELETE /auth/admin/groups/{id}/members/{userId}", a.wrap(a.adminRemoveMember))
	mux.HandleFunc("GET /auth/admin/groups/{id}/members", a.wrap(a.adminGroupMembers))
	mux.HandleFunc("GET /auth/admin/users", a.wrap(a.adminListUsers))
	mux.HandleFunc("POST /auth/admin/users", a.wrap(a.adminCreateUser))
	mux.HandleFunc("POST /auth/admin/users/{id}/disabled", a.wrap(a.adminSetDisabled))
	mux.HandleFunc("POST /auth/admin/users/{id}/password", a.wrap(a.adminSetPassword))
	mux.HandleFunc("POST /auth/admin/users/{id}/ban", a.wrap(a.adminSetBan))
	mux.HandleFunc("DELETE /auth/admin/users/{id}", a.wrap(a.adminDeleteUser))
	mux.HandleFunc("POST /auth/admin/users/{id}/impersonate", a.wrap(a.adminImpersonate))
	mux.HandleFunc("GET /auth/admin/users/{id}/sessions", a.wrap(a.adminListUserSessions))
	mux.HandleFunc("POST /auth/admin/users/{id}/sessions/revoke", a.wrap(a.adminRevokeUserSessions))
	mux.HandleFunc("GET /auth/admin/apikeys", a.wrap(a.adminListKeys))
	mux.HandleFunc("POST /auth/admin/apikeys", a.wrap(a.adminCreateKey))
	mux.HandleFunc("DELETE /auth/admin/apikeys/{id}", a.wrap(a.adminRevokeKey))
}

// paramID reads an opaque entity-id path parameter; on a missing/blank value it writes a 400 and
// returns ok=false so the caller stops. The id is passed to the store verbatim (the store validates
// its own key format) — the auth package never parses it (see AuthUser.ID).
func paramID(c *reqCtx, name string) (string, bool) {
	id := strings.TrimSpace(c.Param(name))
	if id == "" {
		c.JSON(http.StatusBadRequest, H{"error": "invalid " + name})
		return "", false
	}
	return id, true
}

// adminFail logs the internal error (for the operator) and returns a generic message to the client,
// so store internals (SQL text, driver errors) never leak over the admin API.
func (a *Authenticator) adminFail(c *reqCtx, code int, msg string, err error) {
	if err != nil {
		log.Printf("authx admin: %s: %v", msg, err)
	}
	c.JSON(code, H{"error": msg})
}

func (a *Authenticator) adminListGroups(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	gs, err := a.dir.Groups()
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list groups", err)
		return
	}
	c.JSON(http.StatusOK, H{"groups": gs})
}

func (a *Authenticator) adminCreateGroup(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		c.JSON(http.StatusBadRequest, H{"error": "name required"})
		return
	}
	// A duplicate name is a client-side conflict (409); anything else from the store is a 500.
	if existing, gerr := a.dir.GroupByName(strings.TrimSpace(body.Name)); gerr == nil && existing != nil {
		c.JSON(http.StatusConflict, H{"error": "a group with that name already exists"})
		return
	}
	g, err := a.dir.CreateGroup(body.Name, body.Description)
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not create group", err)
		return
	}
	c.JSON(http.StatusOK, g)
}

func (a *Authenticator) adminDeleteGroup(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramID(c, "id")
	if !ok {
		return
	}
	if err := a.dir.DeleteGroup(id); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not delete group", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

func (a *Authenticator) adminAddMember(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	uid, ok := paramID(c, "userId")
	gid, ok2 := paramID(c, "id")
	if !ok || !ok2 {
		return
	}
	if err := a.dir.AddUserToGroup(uid, gid); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not add member", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

func (a *Authenticator) adminRemoveMember(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	uid, ok := paramID(c, "userId")
	gid, ok2 := paramID(c, "id")
	if !ok || !ok2 {
		return
	}
	if err := a.dir.RemoveUserFromGroup(uid, gid); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not remove member", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

func (a *Authenticator) adminGroupMembers(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramID(c, "id")
	if !ok {
		return
	}
	members, err := a.dir.GroupMembers(id)
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list members", err)
		return
	}
	c.JSON(http.StatusOK, H{"members": members})
}

func (a *Authenticator) adminListUsers(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	users, err := a.dir.ListUsers()
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list users", err)
		return
	}
	c.JSON(http.StatusOK, H{"users": users})
}

func (a *Authenticator) adminSetDisabled(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramID(c, "id")
	if !ok {
		return
	}
	var body struct {
		Disabled bool `json:"disabled"`
	}
	_ = c.ShouldBindJSON(&body)
	if err := a.dir.SetUserDisabled(id, body.Disabled); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not update user", err)
		return
	}
	// Parity with ban: when disabling and a SessionStore is wired, cut the user's live sessions so the
	// disable takes effect immediately instead of lingering until the cookie expires.
	if body.Disabled && a.sessions != nil {
		if u, uerr := a.dir.UserByID(id); uerr == nil {
			_ = a.sessions.RevokeAllForUser(u.Sub)
		}
	}
	c.JSON(http.StatusOK, H{"ok": true, "disabled": body.Disabled})
}

func (a *Authenticator) adminListKeys(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	keys, err := a.dir.ListAPIKeys()
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list API keys", err)
		return
	}
	c.JSON(http.StatusOK, H{"apiKeys": keys})
}

func (a *Authenticator) adminCreateKey(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	var body struct {
		Name      string   `json:"name"`
		Groups    []string `json:"groups"`
		Scopes    []string `json:"scopes"`    // deny-by-default: empty grants NOTHING; e.g. ["admin"], ["scim"], ["*"]
		ExpiresAt *string  `json:"expiresAt"` // optional RFC3339
		Org       string   `json:"org"`       // optional org ID or slug: mints an ORG-BOUND key (see APIKeyInfo.OrgID)
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		c.JSON(http.StatusBadRequest, H{"error": "name required"})
		return
	}
	var expires *time.Time
	if body.ExpiresAt != nil && *body.ExpiresAt != "" {
		t, perr := time.Parse(time.RFC3339, *body.ExpiresAt)
		if perr != nil {
			c.JSON(http.StatusBadRequest, H{"error": "expiresAt must be RFC3339"})
			return
		}
		expires = &t
	}
	raw, prefix, hash := generateAPIKey()
	var info *APIKeyInfo
	var err error
	if target := strings.TrimSpace(body.Org); target != "" {
		od := a.orgDir()
		if od == nil || a.orgs == nil {
			c.JSON(http.StatusNotImplemented, H{"error": "org-bound API keys are not available (the stores don't support organizations)"})
			return
		}
		org, oerr := a.resolveOrg(target)
		if errors.Is(oerr, ErrNoOrg) {
			c.JSON(http.StatusNotFound, H{"error": "no such organization"})
			return
		}
		if oerr != nil {
			a.adminFail(c, http.StatusInternalServerError, "could not resolve organization", oerr)
			return
		}
		info, err = od.CreateOrgAPIKey(org.ID, body.Name, body.Groups, body.Scopes, prefix, hash, expires)
	} else {
		info, err = a.dir.CreateAPIKey(body.Name, body.Groups, body.Scopes, prefix, hash, expires)
	}
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not create API key", err)
		return
	}
	// The raw key is returned ONCE here and never again.
	c.JSON(http.StatusOK, H{"key": raw, "apiKey": info})
}

func (a *Authenticator) adminRevokeKey(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramID(c, "id")
	if !ok {
		return
	}
	if err := a.dir.RevokeAPIKey(id); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not revoke API key", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}
