package authx

import (
	"errors"
	"net/http"
	"strings"
)

// adminOrgRoutes mounts the org verbs of the admin REST API (called by routes() when an OrgStore
// is wired). Each handler self-gates via adminGuard. Unlike the self-service /auth/org endpoints,
// the ADMIN verbs skip the last-owner guard — the operator is the recovery path for an org that
// self-service left unmanageable, so the API must be able to reach any state.
func (a *Authenticator) adminOrgRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/admin/orgs", a.wrap(a.adminListOrgs))
	mux.HandleFunc("POST /auth/admin/orgs", a.wrap(a.adminCreateOrg))
	mux.HandleFunc("POST /auth/admin/orgs/{id}", a.wrap(a.adminRenameOrg))
	mux.HandleFunc("DELETE /auth/admin/orgs/{id}", a.wrap(a.adminDeleteOrg))
	mux.HandleFunc("GET /auth/admin/orgs/{id}/members", a.wrap(a.adminOrgMembers))
	mux.HandleFunc("POST /auth/admin/orgs/{id}/members/{userId}", a.wrap(a.adminSetOrgMember))
	mux.HandleFunc("DELETE /auth/admin/orgs/{id}/members/{userId}", a.wrap(a.adminRemoveOrgMember))
}

// paramOrgID reads the opaque org-id path parameter (400 on empty, mirroring paramUint).
func paramOrgID(c *reqCtx) (string, bool) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, H{"error": "invalid id"})
		return "", false
	}
	return id, true
}

func (a *Authenticator) adminListOrgs(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	orgs, err := a.orgs.Orgs()
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not list organizations", err)
		return
	}
	c.JSON(http.StatusOK, H{"orgs": orgs})
}

func (a *Authenticator) adminCreateOrg(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	var body struct{ Slug, Name string }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	slug := strings.ToLower(strings.TrimSpace(body.Slug))
	name := strings.TrimSpace(body.Name)
	if !validOrgSlug(slug) {
		c.JSON(http.StatusBadRequest, H{"error": "slug must be 1–63 chars of a-z, 0-9 or '-', not starting/ending with '-'"})
		return
	}
	if name == "" || len(name) > 128 {
		c.JSON(http.StatusBadRequest, H{"error": "name must be 1–128 characters"})
		return
	}
	// A duplicate slug is a client-side conflict (409); the store's unique constraint stays the
	// fail-closed backstop under races (parity with adminCreateGroup).
	if existing, gerr := a.orgs.OrgBySlug(slug); gerr == nil && existing != nil {
		c.JSON(http.StatusConflict, H{"error": "an organization with that slug already exists"})
		return
	}
	o, err := a.orgs.CreateOrg(slug, name)
	if err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not create organization", err)
		return
	}
	c.JSON(http.StatusOK, o)
}

func (a *Authenticator) adminRenameOrg(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramOrgID(c)
	if !ok {
		return
	}
	var body struct{ Name string }
	_ = c.ShouldBindJSON(&body)
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 128 {
		c.JSON(http.StatusBadRequest, H{"error": "name must be 1–128 characters"})
		return
	}
	if err := a.orgs.RenameOrg(id, name); err != nil {
		if errors.Is(err, ErrNoOrg) {
			c.JSON(http.StatusNotFound, H{"error": "no such organization"})
			return
		}
		a.adminFail(c, http.StatusInternalServerError, "could not rename organization", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true, "name": name})
}

func (a *Authenticator) adminDeleteOrg(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramOrgID(c)
	if !ok {
		return
	}
	if err := a.orgs.DeleteOrg(id); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not delete organization", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

func (a *Authenticator) adminOrgMembers(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramOrgID(c)
	if !ok {
		return
	}
	members, err := a.orgs.OrgMembers(id)
	if err != nil {
		if errors.Is(err, ErrNoOrg) {
			c.JSON(http.StatusNotFound, H{"error": "no such organization"})
			return
		}
		a.adminFail(c, http.StatusInternalServerError, "could not list members", err)
		return
	}
	c.JSON(http.StatusOK, H{"members": members})
}

func (a *Authenticator) adminSetOrgMember(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramOrgID(c)
	if !ok {
		return
	}
	uid, ok := paramUint(c, "userId")
	if !ok {
		return
	}
	var body struct{ Role string }
	_ = c.ShouldBindJSON(&body)
	role, ok := normOrgRole(c, body.Role, OrgRoleMember)
	if !ok {
		return
	}
	if err := a.orgs.SetOrgMember(id, uid, role); err != nil {
		switch {
		case errors.Is(err, ErrNoOrg):
			c.JSON(http.StatusNotFound, H{"error": "no such organization"})
		case errors.Is(err, ErrNoUser):
			// A typo'd user ID must not create a dangling membership a FUTURE auto-increment user
			// would silently inherit (the store refuses; surface it as the 404 it is).
			c.JSON(http.StatusNotFound, H{"error": "no such user"})
		default:
			a.adminFail(c, http.StatusInternalServerError, "could not set member", err)
		}
		return
	}
	c.JSON(http.StatusOK, H{"ok": true, "role": role})
}

func (a *Authenticator) adminRemoveOrgMember(c *reqCtx) {
	if !a.adminGuard(c) {
		return
	}
	id, ok := paramOrgID(c)
	if !ok {
		return
	}
	uid, ok := paramUint(c, "userId")
	if !ok {
		return
	}
	if err := a.orgs.RemoveOrgMember(id, uid); err != nil {
		a.adminFail(c, http.StatusInternalServerError, "could not remove member", err)
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}
