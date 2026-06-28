package authx

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// --- access control: groups (the per-group analog of an IdP's per-client access, for a BFF) ---

// RequireGroupsHTTP is net/http middleware permitting only principals (a session user gated by
// GateHTTP, OR an API key) in at least one of the named groups. Empty names = any authenticated
// principal.
func (a *Authenticator) RequireGroupsHTTP(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hasAnyGroup(a.requestGroups(r), groups) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: requires group membership"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GroupsFromRequest returns the groups of the session attached by GateHTTP.
func GroupsFromRequest(r *http.Request) []string {
	if sc, ok := r.Context().Value(sessionCtxKey).(*SessionClaims); ok && sc != nil {
		return sc.Groups
	}
	return nil
}

// requestGroups returns the groups of whichever principal authenticated the request — the gated
// session user, plus an API key's groups if a valid Bearer key is present.
func (a *Authenticator) requestGroups(r *http.Request) []string {
	have := GroupsFromRequest(r)
	if key := bearerToken(r.Header.Get("Authorization")); key != "" {
		if info, ok := a.ValidateAPIKey(key); ok {
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

// ValidateAPIKeyScope is ValidateAPIKey plus a scope check — convenient for gating a surface (e.g.
// the SCIM server) to keys that carry a specific scope:
//
//	scim.NewServer(store, func(t string) bool { return authn.ValidateAPIKeyScope(t, "scim") })
func (a *Authenticator) ValidateAPIKeyScope(raw, scope string) bool {
	info, ok := a.ValidateAPIKey(raw)
	return ok && KeyHasScope(info, scope)
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
	if key := bearerToken(c.GetHeader("Authorization")); key != "" {
		if info, ok := a.ValidateAPIKey(key); ok && KeyHasScope(info, "admin") {
			return true
		}
		c.JSON(http.StatusForbidden, H{"error": "API key is invalid or lacks the 'admin' scope"})
		return false
	}
	if sc := a.sessionOf(c); sc != nil && a.cfg.OwnerEmail != "" &&
		strings.EqualFold(strings.TrimSpace(sc.Email), a.cfg.OwnerEmail) {
		return true
	}
	c.JSON(http.StatusForbidden, H{"error": "owner session or API key with 'admin' scope required"})
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
	mux.HandleFunc("POST /auth/admin/users/{id}/disabled", a.wrap(a.adminSetDisabled))
	mux.HandleFunc("GET /auth/admin/apikeys", a.wrap(a.adminListKeys))
	mux.HandleFunc("POST /auth/admin/apikeys", a.wrap(a.adminCreateKey))
	mux.HandleFunc("DELETE /auth/admin/apikeys/{id}", a.wrap(a.adminRevokeKey))
}

func paramUint(c *reqCtx, name string) uint {
	n, _ := strconv.ParseUint(c.Param(name), 10, 64)
	return uint(n)
}

func (a *Authenticator) adminListGroups(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	gs, err := a.dir.Groups()
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
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
	g, err := a.dir.CreateGroup(body.Name, body.Description)
	if err != nil {
		c.JSON(http.StatusConflict, H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, g)
}

func (a *Authenticator) adminDeleteGroup(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.DeleteGroup(paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

func (a *Authenticator) adminAddMember(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.AddUserToGroup(paramUint(c, "userId"), paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

func (a *Authenticator) adminRemoveMember(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.RemoveUserFromGroup(paramUint(c, "userId"), paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

func (a *Authenticator) adminGroupMembers(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	members, err := a.dir.GroupMembers(paramUint(c, "id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, H{"users": users})
}

func (a *Authenticator) adminSetDisabled(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	var body struct {
		Disabled bool `json:"disabled"`
	}
	_ = c.ShouldBindJSON(&body)
	if err := a.dir.SetUserDisabled(paramUint(c, "id"), body.Disabled); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true, "disabled": body.Disabled})
}

func (a *Authenticator) adminListKeys(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	keys, err := a.dir.ListAPIKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
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
		Scopes    []string `json:"scopes"`    // optional; empty = unrestricted (e.g. ["admin"], ["scim"])
		ExpiresAt *string  `json:"expiresAt"` // optional RFC3339
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
	info, err := a.dir.CreateAPIKey(body.Name, body.Groups, body.Scopes, prefix, hash, expires)
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
		return
	}
	// The raw key is returned ONCE here and never again.
	c.JSON(http.StatusOK, H{"key": raw, "apiKey": info})
}

func (a *Authenticator) adminRevokeKey(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.RevokeAPIKey(paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}
