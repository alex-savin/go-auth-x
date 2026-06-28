// Package scim is a SCIM 2.0 provisioning server (Users + Groups) over an authx.DirectoryStore, so
// an upstream IdP (Okta, Entra/Azure AD, JumpCloud) can push and deprovision users and groups. It
// implements create / read / list / PATCH / PUT / delete, deprovision via PATCH active=false,
// filtered list (eq / co / sw / pr), the /Bulk endpoint, bearer-token auth, and the discovery
// endpoints. Not implemented: sorting, ETags, and AND/OR-composed filters. Mount it with StripPrefix:
//
//	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scim.NewServer(dir, auth).Handler()))
package scim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"

	authx "github.com/alex-savin/go-auth-x"
)

const (
	schemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList         = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaErr          = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaBulkResponse = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	maxBulkOperations  = 100
)

// Server is a SCIM 2.0 endpoint set backed by a directory.
type Server struct {
	dir  authx.DirectoryStore
	auth func(token string) bool // validates the bearer token (e.g. authn.ValidateAPIKey)
	mux  *http.ServeMux          // the (unauthenticated) route table; /Bulk dispatches sub-requests here
}

// NewServer builds a SCIM server. auth validates the bearer token on every request; pass
// func(t string) bool { _, ok := authn.ValidateAPIKey(t); return ok } to authenticate via API keys.
func NewServer(dir authx.DirectoryStore, auth func(token string) bool) *Server {
	s := &Server{dir: dir, auth: auth}
	s.mux = s.routes()
	return s
}

// Handler returns the SCIM routes (mount under /scim/v2 with http.StripPrefix).
func (s *Server) Handler() http.Handler { return s.authMiddleware(s.mux) }

func (s *Server) routes() *http.ServeMux {
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
	mux.HandleFunc("POST /Bulk", s.bulk)
	return mux
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
	// Filters: `userName`, `emails[.value]`, `externalId` (all map to the email) with eq/co/sw/pr,
	// plus `active eq true|false`. A single term — AND/OR composition isn't supported.
	if f := r.URL.Query().Get("filter"); f != "" {
		flt := parseFilter(f)
		filtered := users[:0]
		for _, u := range users {
			if matchUser(u, flt) {
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
	if f := r.URL.Query().Get("filter"); f != "" { // displayName eq|co|sw|pr "x"
		flt := parseFilter(f)
		filtered := gs[:0]
		for _, g := range gs {
			if matchStr(g.Name, flt.op, flt.value) {
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

// --- bulk ---

// bulk processes a SCIM BulkRequest by dispatching each operation through the normal route table
// (the /Bulk entry is already authenticated, so sub-requests skip auth). Operations apply in order;
// a failing op records its status and the batch continues (failOnErrors is not honored — a v0
// simplification). bulkId cross-references in payloads are not resolved.
func (s *Server) bulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Operations []struct {
			Method string          `json:"method"`
			Path   string          `json:"path"`
			BulkID string          `json:"bulkId"`
			Data   json.RawMessage `json:"data"`
		} `json:"Operations"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		scimError(w, http.StatusBadRequest, "invalid BulkRequest")
		return
	}
	if len(req.Operations) > maxBulkOperations {
		scimError(w, http.StatusRequestEntityTooLarge, "too many bulk operations")
		return
	}
	results := make([]map[string]any, 0, len(req.Operations))
	for _, op := range req.Operations {
		// Reject empty/nested-Bulk operations without dispatching.
		if op.Method == "" || op.Path == "" || strings.EqualFold(strings.Trim(op.Path, "/"), "Bulk") {
			results = append(results, map[string]any{"method": op.Method, "status": "400",
				"response": json.RawMessage(`{"detail":"unsupported bulk operation"}`)})
			continue
		}
		rec := httptest.NewRecorder()
		sub := httptest.NewRequest(strings.ToUpper(op.Method), op.Path, bytes.NewReader(op.Data))
		sub.Header.Set("Content-Type", "application/scim+json")
		s.mux.ServeHTTP(rec, sub)

		res := map[string]any{"method": strings.ToUpper(op.Method), "status": strconv.Itoa(rec.Code)}
		if op.BulkID != "" {
			res["bulkId"] = op.BulkID
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			res["location"] = loc
		} else if rec.Code == http.StatusCreated { // synthesize a location from the created id
			var created struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(rec.Body.Bytes(), &created) == nil && created.ID != "" {
				res["location"] = strings.TrimRight(op.Path, "/") + "/" + created.ID
			}
		}
		if rec.Code >= http.StatusBadRequest {
			res["response"] = json.RawMessage(rec.Body.Bytes())
		}
		results = append(results, res)
	}
	writeSCIM(w, http.StatusOK, map[string]any{"schemas": []string{schemaBulkResponse}, "Operations": results})
}

// --- discovery ---

func (s *Server) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": true, "maxOperations": maxBulkOperations, "maxPayloadSize": 1048576},
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

// scimFilter is a single parsed filter term: `field op value`.
type scimFilter struct {
	field string
	op    string // eq | co | sw | pr
	value string
}

// parseFilter parses a single-term SCIM filter: `field op "value"` (op ∈ eq, co, sw) or the unary
// `field pr` (present). AND/OR composition isn't supported — the first recognized operator wins.
func parseFilter(filter string) scimFilter {
	filter = strings.TrimSpace(filter)
	lower := strings.ToLower(filter)
	for _, op := range []string{"eq", "co", "sw"} {
		if i := strings.Index(lower, " "+op+" "); i >= 0 {
			return scimFilter{
				field: strings.TrimSpace(filter[:i]),
				op:    op,
				value: strings.Trim(strings.TrimSpace(filter[i+len(op)+2:]), `"`),
			}
		}
	}
	if strings.HasSuffix(lower, " pr") {
		return scimFilter{field: strings.TrimSpace(filter[:len(filter)-3]), op: "pr"}
	}
	return scimFilter{op: "eq", value: strings.Trim(filter, `"`)} // lenient bare-value fallback
}

// matchStr applies a SCIM string operator (eq, co, sw, pr) case-insensitively.
func matchStr(have, op, want string) bool {
	h, w := strings.ToLower(have), strings.ToLower(strings.TrimSpace(want))
	switch op {
	case "co":
		return strings.Contains(h, w)
	case "sw":
		return strings.HasPrefix(h, w)
	case "pr":
		return strings.TrimSpace(have) != ""
	default: // eq
		return h == w
	}
}

// matchUser tests a user against a filter term. userName/emails/externalId map to the email;
// `active` is a boolean eq.
func matchUser(u authx.AuthUser, f scimFilter) bool {
	if strings.EqualFold(f.field, "active") {
		return (!u.Disabled) == strings.EqualFold(strings.TrimSpace(f.value), "true")
	}
	return matchStr(u.Email, f.op, f.value)
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
