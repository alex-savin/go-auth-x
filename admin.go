package authx

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// --- access control: groups (the per-client analog for a single-app BFF) ---

const ctxAPIKey = "authxAPIKey" // holds the *APIKeyInfo set by APIKeyAuth

// RequireGroups is Gin middleware that permits only principals (a session user OR an API key) in
// at least one of the named groups. With no names it permits any authenticated principal. Chain it
// after the session middleware (and APIKeyAuth, if you accept API keys on the route).
func (a *Authenticator) RequireGroups(groups ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !hasAnyGroup(a.principalGroups(c), groups) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden: requires group membership"})
			return
		}
		c.Next()
	}
}

// RequireGroupsHTTP is the net/http equivalent (use after GateHTTP).
func (a *Authenticator) RequireGroupsHTTP(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hasAnyGroup(GroupsFromRequest(r), groups) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: requires group membership"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GroupsFromRequest returns the groups of the session gated by GateHTTP.
func GroupsFromRequest(r *http.Request) []string {
	if sc, ok := r.Context().Value(sessionCtxKey).(*SessionClaims); ok && sc != nil {
		return sc.Groups
	}
	return nil
}

// principalGroups returns the groups of whichever principal authenticated this request — the
// session user, or an API key (set by APIKeyAuth).
func (a *Authenticator) principalGroups(c *gin.Context) []string {
	var have []string
	if sc := sessionFrom(c); sc != nil {
		have = append(have, sc.Groups...)
	}
	if v, ok := c.Get(ctxAPIKey); ok {
		if info, ok := v.(*APIKeyInfo); ok {
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

// APIKeyAuth is Gin middleware that authenticates an Authorization: Bearer <key> header against the
// directory. A valid, unexpired key stamps its groups into the context (for RequireGroups + the
// admin guard); an invalid key is rejected; an absent header is a no-op (other auth may apply).
func (a *Authenticator) APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := bearerToken(c.GetHeader("Authorization"))
		if key == "" || a.dir == nil {
			c.Next()
			return
		}
		info, err := a.dir.APIKeyByHash(hashToken(key))
		if err != nil || (info.ExpiresAt != nil && time.Now().After(*info.ExpiresAt)) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired API key"})
			return
		}
		_ = a.dir.TouchAPIKey(info.ID)
		c.Set(ctxAPIKey, info)
		c.Next()
	}
}

// --- admin REST API ---

// adminGuard permits the instance owner (OWNER_EMAIL session) or any valid API key. API keys are
// admin-scoped server-to-server credentials; the owner mints the first one via an owner session.
func (a *Authenticator) adminGuard(c *gin.Context) bool {
	if v, ok := c.Get(ctxAPIKey); ok {
		if info, ok := v.(*APIKeyInfo); ok && KeyHasScope(info, "admin") {
			return true
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "API key lacks the 'admin' scope"})
		return false
	}
	if sc := sessionFrom(c); sc != nil && a.cfg.OwnerEmail != "" &&
		strings.EqualFold(strings.TrimSpace(sc.Email), a.cfg.OwnerEmail) {
		return true
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "owner session or API key with 'admin' scope required"})
	return false
}

// registerAdmin mounts the admin REST API under /auth/admin (called by Register when a directory
// store is wired). Routes accept an owner session or an API key.
func (a *Authenticator) registerAdmin(g gin.IRouter) {
	admin := g.Group("/admin")
	admin.Use(a.APIKeyAuth())
	admin.GET("/groups", a.adminListGroups)
	admin.POST("/groups", a.adminCreateGroup)
	admin.DELETE("/groups/:id", a.adminDeleteGroup)
	admin.POST("/groups/:id/members/:userId", a.adminAddMember)
	admin.DELETE("/groups/:id/members/:userId", a.adminRemoveMember)
	admin.GET("/groups/:id/members", a.adminGroupMembers)
	admin.GET("/users", a.adminListUsers)
	admin.POST("/users/:id/disabled", a.adminSetDisabled)
	admin.GET("/apikeys", a.adminListKeys)
	admin.POST("/apikeys", a.adminCreateKey)
	admin.DELETE("/apikeys/:id", a.adminRevokeKey)
}

func paramUint(c *gin.Context, name string) uint {
	n, _ := strconv.ParseUint(c.Param(name), 10, 64)
	return uint(n)
}

func (a *Authenticator) adminListGroups(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	gs, err := a.dir.Groups()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"groups": gs})
}

func (a *Authenticator) adminCreateGroup(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	g, err := a.dir.CreateGroup(body.Name, body.Description)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, g)
}

func (a *Authenticator) adminDeleteGroup(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.DeleteGroup(paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Authenticator) adminAddMember(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.AddUserToGroup(paramUint(c, "userId"), paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Authenticator) adminRemoveMember(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.RemoveUserFromGroup(paramUint(c, "userId"), paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Authenticator) adminGroupMembers(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	members, err := a.dir.GroupMembers(paramUint(c, "id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"members": members})
}

func (a *Authenticator) adminListUsers(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	users, err := a.dir.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (a *Authenticator) adminSetDisabled(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	var body struct {
		Disabled bool `json:"disabled"`
	}
	_ = c.ShouldBindJSON(&body)
	if err := a.dir.SetUserDisabled(paramUint(c, "id"), body.Disabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "disabled": body.Disabled})
}

func (a *Authenticator) adminListKeys(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	keys, err := a.dir.ListAPIKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"apiKeys": keys})
}

func (a *Authenticator) adminCreateKey(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	var expires *time.Time
	if body.ExpiresAt != nil && *body.ExpiresAt != "" {
		t, perr := time.Parse(time.RFC3339, *body.ExpiresAt)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expiresAt must be RFC3339"})
			return
		}
		expires = &t
	}
	raw, prefix, hash := generateAPIKey()
	info, err := a.dir.CreateAPIKey(body.Name, body.Groups, body.Scopes, prefix, hash, expires)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// The raw key is returned ONCE here and never again.
	c.JSON(http.StatusOK, gin.H{"key": raw, "apiKey": info})
}

func (a *Authenticator) adminRevokeKey(c *gin.Context) {
	if !a.adminGuard(c) {
		return
	}
	if err := a.dir.RevokeAPIKey(paramUint(c, "id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
