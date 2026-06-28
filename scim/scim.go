// Package scim is a minimal SCIM 2.0 provisioning server (Users + Groups) over an
// authx.DirectoryStore, so an upstream IdP (Okta, Entra/Azure AD, JumpCloud) can push and
// deprovision users and groups. It is a pragmatic v0: it implements the create / read / list /
// patch / delete flows those IdPs use (including deprovision via PATCH active=false), bearer-token
// auth, and the discovery endpoints — not the full spec (no PUT replace, complex filters, bulk,
// sorting, or ETags). Mount it with StripPrefix:
//
//	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scim.NewServer(dir, auth).Handler()))
package scim

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	authx "github.com/alex-savin/go-auth-x"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaErr   = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Server is a SCIM 2.0 endpoint set backed by a directory.
type Server struct {
	dir  authx.DirectoryStore
	auth func(token string) bool // validates the bearer token (e.g. authn.ValidateAPIKey)
}

// NewServer builds a SCIM server. auth validates the bearer token on every request; pass
// func(t string) bool { _, ok := authn.ValidateAPIKey(t); return ok } to authenticate via API keys.
func NewServer(dir authx.DirectoryStore, auth func(token string) bool) *Server {
	return &Server{dir: dir, auth: auth}
}

// Handler returns the SCIM routes (mount under /scim/v2 with http.StripPrefix).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ServiceProviderConfig", s.serviceProviderConfig)
	mux.HandleFunc("GET /ResourceTypes", s.resourceTypes)
	mux.HandleFunc("GET /Schemas", s.schemasEndpoint)
	mux.HandleFunc("GET /Users", s.listUsers)
	mux.HandleFunc("POST /Users", s.createUser)
	mux.HandleFunc("GET /Users/{id}", s.getUser)
	mux.HandleFunc("PUT /Users/{id}", s.putUser)
	mux.HandleFunc("PATCH /Users/{id}", s.patchUser)
	mux.HandleFunc("DELETE /Users/{id}", s.deleteUser)
	mux.HandleFunc("GET /Groups", s.listGroups)
	mux.HandleFunc("POST /Groups", s.createGroup)
	mux.HandleFunc("GET /Groups/{id}", s.getGroup)
	mux.HandleFunc("PUT /Groups/{id}", s.putGroup)
	mux.HandleFunc("PATCH /Groups/{id}", s.patchGroup)
	mux.HandleFunc("DELETE /Groups/{id}", s.deleteGroup)
	return s.authMiddleware(mux)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.auth == nil || !s.auth(strings.TrimSpace(tok)) {
			scimError(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- JSON shapes ---

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}

type scimUser struct {
	Schemas  []string    `json:"schemas"`
	ID       string      `json:"id"`
	UserName string      `json:"userName"`
	Name     *scimName   `json:"name,omitempty"`
	Emails   []scimEmail `json:"emails,omitempty"`
	Active   bool        `json:"active"`
	Meta     scimMeta    `json:"meta"`
}

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type scimGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members,omitempty"`
	Meta        scimMeta     `json:"meta"`
}

type patchOp struct {
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

// --- helpers ---

func writeSCIM(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(obj)
}

func scimError(w http.ResponseWriter, code int, detail string) {
	writeSCIM(w, code, map[string]any{"schemas": []string{schemaErr}, "status": strconv.Itoa(code), "detail": detail})
}

func toSCIMUser(u *authx.AuthUser) scimUser {
	return scimUser{
		Schemas: []string{schemaUser}, ID: strconv.FormatUint(uint64(u.ID), 10), UserName: u.Email,
		Name:   &scimName{Formatted: u.Name},
		Emails: []scimEmail{{Value: u.Email, Primary: true}},
		Active: !u.Disabled, Meta: scimMeta{ResourceType: "User"},
	}
}

func toSCIMGroup(g authx.Group, members []authx.AuthUser) scimGroup {
	ms := make([]scimMember, 0, len(members))
	for _, m := range members {
		ms = append(ms, scimMember{Value: strconv.FormatUint(uint64(m.ID), 10), Display: m.Email})
	}
	return scimGroup{Schemas: []string{schemaGroup}, ID: strconv.FormatUint(uint64(g.ID), 10), DisplayName: g.Name, Members: ms, Meta: scimMeta{ResourceType: "Group"}}
}

func pathID(r *http.Request) uint {
	n, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	return uint(n)
}

// --- Users ---

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.dir.ListUsers()
	if err != nil {
		scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Filters: `userName eq`, `emails[.value] eq`, `externalId eq` (all map to the email), and
	// `active eq true|false`. Only the `eq` operator is supported.
	if f := r.URL.Query().Get("filter"); f != "" {
		field, want := parseEqFilter(f)
		filtered := users[:0]
		for _, u := range users {
			match := strings.EqualFold(u.Email, want)
			if strings.EqualFold(field, "active") {
				match = (!u.Disabled) == strings.EqualFold(want, "true")
			}
			if match {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}
	resources := make([]scimUser, 0, len(users))
	for i := range users {
		resources = append(resources, toSCIMUser(&users[i]))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas": []string{schemaList}, "totalResults": len(resources),
		"startIndex": 1, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in scimUser
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.UserName == "" {
		scimError(w, http.StatusBadRequest, "userName required")
		return
	}
	email := in.UserName
	if len(in.Emails) > 0 && in.Emails[0].Value != "" {
		email = in.Emails[0].Value
	}
	name := in.UserName
	if in.Name != nil && in.Name.Formatted != "" {
		name = in.Name.Formatted
	}
	u, err := s.dir.UpsertExternalUser("scim:"+in.UserName, email, name, true)
	if err != nil {
		scimError(w, http.StatusConflict, err.Error())
		return
	}
	if in.Active != !u.Disabled {
		_ = s.dir.SetUserDisabled(u.ID, !in.Active)
		u.Disabled = !in.Active
	}
	writeSCIM(w, http.StatusCreated, toSCIMUser(u))
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.dir.UserByID(pathID(r))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, toSCIMUser(u))
}

// patchUser handles the deprovision/reactivate flow (replace active=true/false).
func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if _, err := s.dir.UserByID(id); err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	var p patchOp
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		scimError(w, http.StatusBadRequest, "invalid PatchOp")
		return
	}
	for _, op := range p.Operations {
		if active, ok := activeFromOp(op.Path, op.Value); ok {
			_ = s.dir.SetUserDisabled(id, !active)
		}
	}
	u, _ := s.dir.UserByID(id)
	writeSCIM(w, http.StatusOK, toSCIMUser(u))
}

// putUser replaces a user (name + active; email/userName too). The Sub is preserved.
func (s *Server) putUser(w http.ResponseWriter, r *http.Request) {
	cur, err := s.dir.UserByID(pathID(r))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	var in scimUser
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.UserName == "" {
		scimError(w, http.StatusBadRequest, "userName required")
		return
	}
	email := in.UserName
	if len(in.Emails) > 0 && in.Emails[0].Value != "" {
		email = in.Emails[0].Value
	}
	name := in.UserName
	if in.Name != nil && in.Name.Formatted != "" {
		name = in.Name.Formatted
	}
	if _, uerr := s.dir.UpsertExternalUser(cur.Sub, email, name, true); uerr != nil { // preserve Sub
		scimError(w, http.StatusInternalServerError, uerr.Error())
		return
	}
	_ = s.dir.SetUserDisabled(cur.ID, !in.Active)
	u, _ := s.dir.UserByID(cur.ID)
	writeSCIM(w, http.StatusOK, toSCIMUser(u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	// SCIM DELETE = deprovision; we soft-disable (safer than a hard delete of audit history).
	if err := s.dir.SetUserDisabled(pathID(r), true); err != nil {
		scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Groups ---

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := s.dir.Groups()
	if err != nil {
		scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f := r.URL.Query().Get("filter"); f != "" { // displayName eq "x"
		_, want := parseEqFilter(f)
		filtered := gs[:0]
		for _, g := range gs {
			if strings.EqualFold(g.Name, want) {
				filtered = append(filtered, g)
			}
		}
		gs = filtered
	}
	resources := make([]scimGroup, 0, len(gs))
	for _, g := range gs {
		members, _ := s.dir.GroupMembers(g.ID)
		resources = append(resources, toSCIMGroup(g, members))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas": []string{schemaList}, "totalResults": len(resources),
		"startIndex": 1, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in scimGroup
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.DisplayName == "" {
		scimError(w, http.StatusBadRequest, "displayName required")
		return
	}
	g, err := s.dir.GroupByName(in.DisplayName)
	if err == authx.ErrNoGroup {
		g, err = s.dir.CreateGroup(in.DisplayName, "provisioned via SCIM")
	}
	if err != nil {
		scimError(w, http.StatusConflict, err.Error())
		return
	}
	for _, m := range in.Members {
		if uid, e := strconv.ParseUint(m.Value, 10, 64); e == nil {
			_ = s.dir.AddUserToGroup(uint(uid), g.ID)
		}
	}
	members, _ := s.dir.GroupMembers(g.ID)
	writeSCIM(w, http.StatusCreated, toSCIMGroup(*g, members))
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	gs, _ := s.dir.Groups()
	for _, g := range gs {
		if g.ID == id {
			members, _ := s.dir.GroupMembers(id)
			writeSCIM(w, http.StatusOK, toSCIMGroup(g, members))
			return
		}
	}
	scimError(w, http.StatusNotFound, "group not found")
}

// putGroup replaces a group's membership with the provided set (the canonical Okta/Azure group
// PUT). Group rename isn't persisted (the directory has no rename); displayName is echoed back.
func (s *Server) putGroup(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	var in scimGroup
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		scimError(w, http.StatusBadRequest, "invalid Group")
		return
	}
	want := map[uint]bool{}
	for _, m := range in.Members {
		if uid, e := strconv.ParseUint(m.Value, 10, 64); e == nil {
			want[uint(uid)] = true
		}
	}
	current, _ := s.dir.GroupMembers(id)
	for _, m := range current { // remove members no longer present
		if !want[m.ID] {
			_ = s.dir.RemoveUserFromGroup(m.ID, id)
		}
	}
	for uid := range want { // add the desired set (idempotent)
		_ = s.dir.AddUserToGroup(uid, id)
	}
	members, _ := s.dir.GroupMembers(id)
	writeSCIM(w, http.StatusOK, toSCIMGroup(authx.Group{ID: id, Name: in.DisplayName}, members))
}

// patchGroup handles membership add/remove operations.
func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	var p patchOp
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		scimError(w, http.StatusBadRequest, "invalid PatchOp")
		return
	}
	for _, op := range p.Operations {
		if !strings.EqualFold(op.Path, "members") {
			continue
		}
		for _, uid := range memberValues(op.Value) {
			switch strings.ToLower(op.Op) {
			case "add", "replace":
				_ = s.dir.AddUserToGroup(uid, id)
			case "remove":
				_ = s.dir.RemoveUserFromGroup(uid, id)
			}
		}
	}
	members, _ := s.dir.GroupMembers(id)
	writeSCIM(w, http.StatusOK, toSCIMGroup(authx.Group{ID: id}, members))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.dir.DeleteGroup(pathID(r)); err != nil {
		scimError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- discovery ---

func (s *Server) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": false},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "Bearer Token"}},
	})
}

func (s *Server) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": schemaUser},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup},
	})
}

func (s *Server) schemasEndpoint(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, []map[string]any{{"id": schemaUser, "name": "User"}, {"id": schemaGroup, "name": "Group"}})
}

// --- tiny parsers ---

// parseEqFilter parses a SCIM `field eq "value"` filter into its field + value. Only `eq` is
// supported (the operator IdPs use for user/group lookups).
func parseEqFilter(filter string) (field, value string) {
	lower := strings.ToLower(filter)
	i := strings.Index(lower, " eq ")
	if i < 0 {
		return "", strings.Trim(strings.TrimSpace(filter), `"`)
	}
	return strings.TrimSpace(filter[:i]), strings.Trim(strings.TrimSpace(filter[i+4:]), `"`)
}

// activeFromOp returns the boolean for an `active` replace op (path "active", or value {"active":x}).
func activeFromOp(path string, value json.RawMessage) (bool, bool) {
	if strings.EqualFold(path, "active") {
		var b bool
		if json.Unmarshal(value, &b) == nil {
			return b, true
		}
	}
	var m map[string]any
	if json.Unmarshal(value, &m) == nil {
		if v, ok := m["active"].(bool); ok {
			return v, true
		}
	}
	return false, false
}

// memberValues extracts user ids from a members patch value ([{value:"1"}] or {value:"1"}).
func memberValues(value json.RawMessage) []uint {
	var arr []scimMember
	if json.Unmarshal(value, &arr) == nil && len(arr) > 0 {
		return idsOf(arr)
	}
	var one scimMember
	if json.Unmarshal(value, &one) == nil && one.Value != "" {
		return idsOf([]scimMember{one})
	}
	return nil
}

func idsOf(ms []scimMember) []uint {
	var out []uint
	for _, m := range ms {
		if id, err := strconv.ParseUint(m.Value, 10, 64); err == nil {
			out = append(out, uint(id))
		}
	}
	return out
}
