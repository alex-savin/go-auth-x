// Package scim is a SCIM 2.0 provisioning server (Users + Groups) over an authx.DirectoryStore, so
// an upstream IdP (Okta, Entra/Azure AD, JumpCloud) can push and deprovision users and groups. It
// implements create / read / list / PATCH / PUT / delete, deprovision via PATCH active=false,
// filtered list (eq/ne/co/sw/ew/pr with and/or/not/parens composition), sorting (sortBy/sortOrder),
// ETags with If-Match / If-None-Match, the /Bulk endpoint, bearer-token auth, and the discovery
// endpoints. Filtering covers eq/ne/co/sw/ew/gt/ge/lt/le/pr with and/or/not composition, parentheses,
// and valuePath (emails[type eq "work"]). Mount it with StripPrefix:
//
//	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scim.NewServer(dir, auth).Handler()))
package scim

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	authx "github.com/alex-savin/go-auth-x"
)

// maxBodyBytes caps a SCIM request body to defend against memory-exhaustion from an unbounded read.
const maxBodyBytes = 1 << 20 // 1 MiB (matches the advertised bulk maxPayloadSize)

// readBody reads at most maxBodyBytes of the request body.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
}

// scimInternal logs the real error and returns a generic 500, so internal (e.g. GORM) error strings
// never leak to the SCIM client.
func scimInternal(w http.ResponseWriter, context string, err error) {
	log.Printf("scim: %s: %v", context, err)
	scimError(w, http.StatusInternalServerError, "internal error")
}

// activeWithDefault reads the optional SCIM `active` field, defaulting to true when it is ABSENT
// (RFC 7644 — a create/replace that omits active must not disable the account).
func activeWithDefault(raw []byte) bool {
	var probe struct {
		Active *bool `json:"active"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.Active == nil || *probe.Active
}

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
	dir     authx.DirectoryStore
	auth    func(token string) bool // validates the bearer token (e.g. authn.ValidateAPIKey)
	mux     *http.ServeMux          // the (unauthenticated) route table; /Bulk dispatches sub-requests here
	baseURL string                  // externally-visible SCIM root, for Location / meta.location
}

// SetBaseURL sets the externally-visible SCIM root (e.g. "https://app.example.com/scim/v2") used to
// build the resource Location header + meta.location (RFC 7644 §3.1/§3.3). Optional — when unset,
// those fields are omitted.
func (s *Server) SetBaseURL(u string) { s.baseURL = strings.TrimRight(u, "/") }

// loc builds a resource URL, or "" when no base URL is configured.
func (s *Server) loc(kind, id string) string {
	if s.baseURL == "" {
		return ""
	}
	return s.baseURL + "/" + kind + "/" + id
}

// NewServer builds a SCIM server. auth validates the bearer token on every request; pass a
// scope-checking closure so only keys granted the "scim" scope may provision:
//
//	func(t string) bool { return authn.ValidateAPIKeyScope(t, "scim") }
//
// (Prefer this over the scopeless ValidateAPIKey, which would admit any valid key regardless of scope.)
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
	mux.HandleFunc("GET /Schemas/{id}", s.schemaByID)
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
		// Cap every request body so an unbounded JSON payload can't exhaust memory.
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
	Created      string `json:"created,omitempty"`      // RFC3339; omitted if the store has no timestamp
	LastModified string `json:"lastModified,omitempty"` // RFC3339
	Location     string `json:"location,omitempty"`
	Version      string `json:"version,omitempty"` // strong ETag
}

// scimTime formats a timestamp as SCIM/RFC3339 (UTC); a zero time yields "" (omitted via omitempty).
func scimTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// lastModified is UpdatedAt when set, else the creation time (a never-updated resource).
func lastModified(created, updated time.Time) time.Time {
	if updated.IsZero() {
		return created
	}
	return updated
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

// scimErrorType is scimError with a SCIM "scimType" (e.g. "invalidFilter").
func scimErrorType(w http.ResponseWriter, code int, scimType, detail string) {
	writeSCIM(w, code, map[string]any{"schemas": []string{schemaErr}, "scimType": scimType, "status": strconv.Itoa(code), "detail": detail})
}

// listEnvelope wraps a page of resources in a SCIM ListResponse (RFC 7644 §3.4.2). totalResults is
// the full match count (before paging); startIndex is the 1-based index of the first returned item.
func listEnvelope[T any](resources []T, totalResults, startIndex int) map[string]any {
	return map[string]any{
		"schemas": []string{schemaList}, "totalResults": totalResults,
		"startIndex": startIndex, "itemsPerPage": len(resources), "Resources": resources,
	}
}

// parsePaging reads SCIM startIndex/count (RFC 7644 §3.4.2.4). startIndex is 1-based (min 1,
// default 1). An absent count → -1 (return all remaining); a present count is clamped to ≥0
// (count=0 is a valid "how many match?" query that returns totalResults with an empty page).
func parsePaging(startIndexRaw, countRaw string) (startIndex, count int) {
	startIndex = 1
	if n, err := strconv.Atoi(startIndexRaw); err == nil && n > 1 {
		startIndex = n
	}
	count = -1
	if countRaw != "" {
		if n, err := strconv.Atoi(countRaw); err == nil {
			if n < 0 {
				n = 0
			}
			count = n
		}
	}
	return
}

// paginate applies startIndex/count to a filtered+sorted slice, returning the page and the
// effective 1-based start index. count < 0 returns all remaining from startIndex.
func paginate[T any](all []T, startIndex, count int) ([]T, int) {
	if startIndex < 1 {
		startIndex = 1
	}
	lo := startIndex - 1
	if lo > len(all) {
		lo = len(all)
	}
	rest := all[lo:]
	if count < 0 || count > len(rest) {
		return rest, startIndex
	}
	return rest[:count], startIndex
}

func (s *Server) toSCIMUser(u *authx.AuthUser) scimUser {
	id := strconv.FormatUint(uint64(u.ID), 10)
	return scimUser{
		Schemas: []string{schemaUser}, ID: id, UserName: u.Email,
		Name:   &scimName{Formatted: u.Name},
		Emails: []scimEmail{{Value: u.Email, Primary: true}},
		Active: !u.Disabled, Meta: scimMeta{
			ResourceType: "User", Created: scimTime(u.CreatedAt),
			LastModified: scimTime(lastModified(u.CreatedAt, u.UpdatedAt)),
			Location:     s.loc("Users", id), Version: userVersion(u),
		},
	}
}

func (s *Server) toSCIMGroup(g authx.Group, members []authx.AuthUser) scimGroup {
	id := strconv.FormatUint(uint64(g.ID), 10)
	ms := make([]scimMember, 0, len(members))
	for _, m := range members {
		ms = append(ms, scimMember{Value: strconv.FormatUint(uint64(m.ID), 10), Display: m.Email})
	}
	return scimGroup{Schemas: []string{schemaGroup}, ID: id, DisplayName: g.Name, Members: ms, Meta: scimMeta{
		ResourceType: "Group", Created: scimTime(g.CreatedAt),
		LastModified: scimTime(lastModified(g.CreatedAt, g.UpdatedAt)),
		Location:     s.loc("Groups", id), Version: groupVersion(g, members),
	}}
}

func pathID(r *http.Request) uint {
	n, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	return uint(n)
}

// --- Users ---

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.dir.ListUsers()
	if err != nil {
		scimInternal(w, "listUsers", err)
		return
	}
	// Filtering: boolean-composed (and / or / not / parens) over eq/ne/co/sw/ew/pr on userName,
	// emails, externalId (→ email), active, and id. Plus sortBy / sortOrder.
	q := r.URL.Query()
	if f := q.Get("filter"); f != "" {
		p, ferr := compileFilter(f)
		if ferr != nil {
			scimErrorType(w, http.StatusBadRequest, "invalidFilter", "invalid filter: "+ferr.Error())
			return
		}
		filtered := users[:0]
		for i := range users {
			if p(userResource(&users[i])) {
				filtered = append(filtered, users[i])
			}
		}
		users = filtered
	}
	sortUsers(users, q.Get("sortBy"), q.Get("sortOrder"))
	total := len(users)
	si, cnt := parsePaging(q.Get("startIndex"), q.Get("count"))
	pageUsers, start := paginate(users, si, cnt)
	resources := make([]scimUser, 0, len(pageUsers))
	for i := range pageUsers {
		resources = append(resources, s.toSCIMUser(&pageUsers[i]))
	}
	writeSCIM(w, http.StatusOK, listEnvelope(resources, total, start))
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	raw, rerr := readBody(w, r)
	var in scimUser
	if rerr != nil || json.Unmarshal(raw, &in) != nil || in.UserName == "" {
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
	// A SCIM CREATE must be a create, not the login-time upsert: pre-check email uniqueness and refuse any
	// collision with 409 uniqueness (RFC 7644 §3.3). Without this, UpsertExternalUser's account-linking
	// rule would silently REBIND a verified existing user's Sub (orphaning their sessions/data) or
	// destructively cascade-delete an unverified row's credentials — data loss from a provisioning CREATE.
	if existing, cerr := s.dir.UserByEmail(email); cerr == nil && existing != nil {
		scimErrorType(w, http.StatusConflict, "uniqueness", "a user with this email already exists")
		return
	} else if cerr != nil && !errors.Is(cerr, authx.ErrNoUser) {
		scimInternal(w, "createUser", cerr)
		return
	}
	u, err := s.dir.UpsertExternalUser("scim:"+in.UserName, email, name, true)
	if err != nil {
		if errors.Is(err, authx.ErrEmailConflict) {
			scimErrorType(w, http.StatusConflict, "uniqueness", "a user with this email already exists")
		} else {
			scimInternal(w, "createUser", err)
		}
		return
	}
	active := activeWithDefault(raw) // absent → true (never disable a freshly created user)
	if active != !u.Disabled {
		_ = s.dir.SetUserDisabled(u.ID, !active)
		u.Disabled = !active
	}
	res := s.toSCIMUser(u)
	if res.Meta.Location != "" {
		w.Header().Set("Location", res.Meta.Location) // RFC 7644 §3.3
	}
	writeResource(w, http.StatusCreated, res, userVersion(u))
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.dir.UserByID(pathID(r))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	v := userVersion(u)
	if ifNoneMatchSatisfied(r, v) {
		w.Header().Set("ETag", v)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeResource(w, http.StatusOK, s.toSCIMUser(u), v)
}

// validatePatchOps enforces the RFC 7644 §3.5.2 op grammar: op ∈ add|remove|replace, and a `remove`
// MUST target a path. Returns a scimType + detail (ok=false) on the first violation.
func validatePatchOps(p patchOp) (scimType, detail string, ok bool) {
	for _, op := range p.Operations {
		switch strings.ToLower(op.Op) {
		case "add", "replace":
		case "remove":
			if strings.TrimSpace(op.Path) == "" {
				return "noTarget", "a 'remove' operation requires a path", false
			}
		default:
			return "invalidValue", "unsupported PATCH op: " + op.Op, false
		}
	}
	return "", "", true
}

// patchUser handles the deprovision/reactivate flow (replace active=true/false).
func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	cur, err := s.dir.UserByID(id)
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	if ifMatchFails(r, userVersion(cur)) {
		scimError(w, http.StatusPreconditionFailed, "ETag precondition failed")
		return
	}
	var p patchOp
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		scimError(w, http.StatusBadRequest, "invalid PatchOp")
		return
	}
	if st, detail, ok := validatePatchOps(p); !ok {
		scimErrorType(w, http.StatusBadRequest, st, detail)
		return
	}
	for _, op := range p.Operations {
		if active, ok := activeFromOp(op.Path, op.Value); ok {
			_ = s.dir.SetUserDisabled(id, !active)
		}
	}
	u, _ := s.dir.UserByID(id)
	writeResource(w, http.StatusOK, s.toSCIMUser(u), userVersion(u))
}

// putUser replaces a user (name + active; email/userName too). The Sub is preserved.
func (s *Server) putUser(w http.ResponseWriter, r *http.Request) {
	cur, err := s.dir.UserByID(pathID(r))
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	if ifMatchFails(r, userVersion(cur)) {
		scimError(w, http.StatusPreconditionFailed, "ETag precondition failed")
		return
	}
	raw, rerr := readBody(w, r)
	var in scimUser
	if rerr != nil || json.Unmarshal(raw, &in) != nil || in.UserName == "" {
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
		if errors.Is(uerr, authx.ErrEmailConflict) { // PUT would move this user onto another's email
			scimErrorType(w, http.StatusConflict, "uniqueness", "a user with this email already exists")
			return
		}
		scimInternal(w, "putUser", uerr)
		return
	}
	_ = s.dir.SetUserDisabled(cur.ID, !activeWithDefault(raw)) // absent → true
	u, _ := s.dir.UserByID(cur.ID)
	writeResource(w, http.StatusOK, s.toSCIMUser(u), userVersion(u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if r.Header.Get("If-Match") != "" { // optimistic-concurrency precondition
		if cur, err := s.dir.UserByID(id); err == nil && ifMatchFails(r, userVersion(cur)) {
			scimError(w, http.StatusPreconditionFailed, "ETag precondition failed")
			return
		}
	}
	// SCIM DELETE = deprovision; we soft-disable (safer than a hard delete of audit history).
	if err := s.dir.SetUserDisabled(id, true); err != nil {
		scimInternal(w, "deleteUser", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Groups ---

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := s.dir.Groups()
	if err != nil {
		scimInternal(w, "listGroups", err)
		return
	}
	q := r.URL.Query()
	if f := q.Get("filter"); f != "" { // displayName / id with eq/ne/co/sw/ew/pr + and/or/not
		p, ferr := compileFilter(f)
		if ferr != nil {
			scimErrorType(w, http.StatusBadRequest, "invalidFilter", "invalid filter: "+ferr.Error())
			return
		}
		filtered := gs[:0]
		for i := range gs {
			g := gs[i]
			if p(groupResource(&g, func() []authx.AuthUser { m, _ := s.dir.GroupMembers(g.ID); return m })) {
				filtered = append(filtered, gs[i])
			}
		}
		gs = filtered
	}
	sortGroups(gs, q.Get("sortBy"), q.Get("sortOrder"))
	total := len(gs)
	si, cnt := parsePaging(q.Get("startIndex"), q.Get("count"))
	pageGroups, start := paginate(gs, si, cnt)
	resources := make([]scimGroup, 0, len(pageGroups))
	for _, g := range pageGroups {
		members, _ := s.dir.GroupMembers(g.ID)
		resources = append(resources, s.toSCIMGroup(g, members))
	}
	writeSCIM(w, http.StatusOK, listEnvelope(resources, total, start))
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	raw, rerr := readBody(w, r)
	var in scimGroup
	if rerr != nil || json.Unmarshal(raw, &in) != nil || in.DisplayName == "" {
		scimError(w, http.StatusBadRequest, "displayName required")
		return
	}
	// A duplicate displayName is a uniqueness conflict (RFC 7644 §3.3), not an idempotent create.
	if existing, gerr := s.dir.GroupByName(in.DisplayName); gerr == nil && existing != nil {
		scimErrorType(w, http.StatusConflict, "uniqueness", "a group with this displayName already exists")
		return
	} else if gerr != nil && !errors.Is(gerr, authx.ErrNoGroup) {
		scimInternal(w, "createGroup lookup", gerr)
		return
	}
	g, err := s.dir.CreateGroup(in.DisplayName, "provisioned via SCIM")
	if err != nil {
		scimInternal(w, "createGroup", err)
		return
	}
	for _, m := range in.Members {
		if uid, e := strconv.ParseUint(m.Value, 10, 64); e == nil {
			_ = s.dir.AddUserToGroup(uint(uid), g.ID)
		}
	}
	members, _ := s.dir.GroupMembers(g.ID)
	res := s.toSCIMGroup(*g, members)
	if res.Meta.Location != "" {
		w.Header().Set("Location", res.Meta.Location) // RFC 7644 §3.3
	}
	writeResource(w, http.StatusCreated, res, groupVersion(*g, members))
}

// groupByID finds a group + its members by id (the DirectoryStore has no GroupByID lookup).
func (s *Server) groupByID(id uint) (authx.Group, []authx.AuthUser, bool) {
	gs, _ := s.dir.Groups()
	for _, g := range gs {
		if g.ID == id {
			members, _ := s.dir.GroupMembers(id)
			return g, members, true
		}
	}
	return authx.Group{}, nil, false
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	g, members, ok := s.groupByID(pathID(r))
	if !ok {
		scimError(w, http.StatusNotFound, "group not found")
		return
	}
	v := groupVersion(g, members)
	if ifNoneMatchSatisfied(r, v) {
		w.Header().Set("ETag", v)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeResource(w, http.StatusOK, s.toSCIMGroup(g, members), v)
}

// putGroup replaces a group's membership with the provided set (the canonical Okta/Azure group
// PUT). Group rename isn't persisted (the directory has no rename); displayName is echoed back.
func (s *Server) putGroup(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if r.Header.Get("If-Match") != "" {
		if g, members, ok := s.groupByID(id); ok && ifMatchFails(r, groupVersion(g, members)) {
			scimError(w, http.StatusPreconditionFailed, "ETag precondition failed")
			return
		}
	}
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
	g, members, ok := s.groupByID(id)
	if !ok {
		g, members = authx.Group{ID: id, Name: in.DisplayName}, nil
	}
	writeResource(w, http.StatusOK, s.toSCIMGroup(g, members), groupVersion(g, members))
}

// patchGroup handles membership add/remove operations.
func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if r.Header.Get("If-Match") != "" {
		if g, members, ok := s.groupByID(id); ok && ifMatchFails(r, groupVersion(g, members)) {
			scimError(w, http.StatusPreconditionFailed, "ETag precondition failed")
			return
		}
	}
	var p patchOp
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		scimError(w, http.StatusBadRequest, "invalid PatchOp")
		return
	}
	if st, detail, ok := validatePatchOps(p); !ok {
		scimErrorType(w, http.StatusBadRequest, st, detail)
		return
	}
	for _, op := range p.Operations {
		opl := strings.ToLower(op.Op)
		pathl := strings.ToLower(strings.TrimSpace(op.Path))

		// valuePath removal: members[value eq "42"] (the Okta/Azure single-member remove).
		if strings.HasPrefix(pathl, "members[") {
			if opl == "remove" {
				if uid, ok := memberIDFromValuePath(op.Path); ok {
					_ = s.dir.RemoveUserFromGroup(uid, id)
				}
			}
			continue
		}
		if pathl != "members" {
			continue
		}
		switch opl {
		case "add":
			for _, uid := range memberValues(op.Value) {
				_ = s.dir.AddUserToGroup(uid, id)
			}
		case "replace":
			// Replace the ENTIRE membership set with the provided one (not merely additive).
			want := map[uint]bool{}
			for _, uid := range memberValues(op.Value) {
				want[uid] = true
			}
			current, _ := s.dir.GroupMembers(id)
			for _, m := range current {
				if !want[m.ID] {
					_ = s.dir.RemoveUserFromGroup(m.ID, id)
				}
			}
			for uid := range want {
				_ = s.dir.AddUserToGroup(uid, id)
			}
		case "remove":
			if len(op.Value) == 0 || string(op.Value) == "null" {
				// `remove` on "members" with no value → clear all members.
				current, _ := s.dir.GroupMembers(id)
				for _, m := range current {
					_ = s.dir.RemoveUserFromGroup(m.ID, id)
				}
			} else {
				for _, uid := range memberValues(op.Value) {
					_ = s.dir.RemoveUserFromGroup(uid, id)
				}
			}
		}
	}
	g, members, ok := s.groupByID(id)
	if !ok {
		g, members = authx.Group{ID: id}, nil
	}
	writeResource(w, http.StatusOK, s.toSCIMGroup(g, members), groupVersion(g, members))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if r.Header.Get("If-Match") != "" { // optimistic-concurrency precondition
		if g, members, ok := s.groupByID(id); ok && ifMatchFails(r, groupVersion(g, members)) {
			scimError(w, http.StatusPreconditionFailed, "ETag precondition failed")
			return
		}
	}
	if err := s.dir.DeleteGroup(id); err != nil {
		scimInternal(w, "deleteGroup", err)
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
		"sort":                  map[string]bool{"supported": true},
		"etag":                  map[string]bool{"supported": true},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "Bearer Token"}},
	})
}

func (s *Server) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": schemaUser},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup},
	})
}

// schemasEndpoint returns the supported resource schemas as a SCIM ListResponse (RFC 7644 §4).
func (s *Server) schemasEndpoint(w http.ResponseWriter, _ *http.Request) {
	docs := schemaDocs()
	writeSCIM(w, http.StatusOK, listEnvelope(docs, len(docs), 1))
}

// schemaByID serves a single schema document by URN (RFC 7644 §4), 404 if unknown.
func (s *Server) schemaByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, doc := range schemaDocs() {
		if doc["id"] == id {
			writeSCIM(w, http.StatusOK, doc)
			return
		}
	}
	scimError(w, http.StatusNotFound, "no such schema: "+id)
}

// scimAttr builds one attribute descriptor for a schema document (RFC 7643 §7).
func scimAttr(name, typ string, multi, required, caseExact bool, mutability, returned, uniqueness string) map[string]any {
	return map[string]any{
		"name": name, "type": typ, "multiValued": multi, "required": required,
		"caseExact": caseExact, "mutability": mutability, "returned": returned, "uniqueness": uniqueness,
	}
}

// schemaDocs returns the full User + Group core schema documents this server actually supports.
func schemaDocs() []map[string]any {
	userAttrs := []map[string]any{
		scimAttr("userName", "string", false, true, false, "readWrite", "default", "server"),
		{
			"name": "name", "type": "complex", "multiValued": false, "required": false,
			"mutability": "readWrite", "returned": "default", "uniqueness": "none",
			"subAttributes": []map[string]any{
				scimAttr("formatted", "string", false, false, false, "readWrite", "default", "none"),
			},
		},
		{
			"name": "emails", "type": "complex", "multiValued": true, "required": false,
			"mutability": "readWrite", "returned": "default", "uniqueness": "none",
			"subAttributes": []map[string]any{
				scimAttr("value", "string", false, false, false, "readWrite", "default", "none"),
				scimAttr("primary", "boolean", false, false, false, "readWrite", "default", "none"),
			},
		},
		scimAttr("active", "boolean", false, false, false, "readWrite", "default", "none"),
	}
	groupAttrs := []map[string]any{
		scimAttr("displayName", "string", false, true, false, "readWrite", "default", "none"),
		{
			"name": "members", "type": "complex", "multiValued": true, "required": false,
			"mutability": "readWrite", "returned": "default", "uniqueness": "none",
			"subAttributes": []map[string]any{
				scimAttr("value", "string", false, false, false, "immutable", "default", "none"),
				scimAttr("display", "string", false, false, false, "immutable", "default", "none"),
			},
		},
	}
	return []map[string]any{
		{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":      schemaUser, "name": "User", "description": "User Account",
			"attributes": userAttrs,
			"meta":       map[string]any{"resourceType": "Schema", "location": "/Schemas/" + schemaUser},
		},
		{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":      schemaGroup, "name": "Group", "description": "Group",
			"attributes": groupAttrs,
			"meta":       map[string]any{"resourceType": "Schema", "location": "/Schemas/" + schemaGroup},
		},
	}
}

// --- patch / member-value parsers ---

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

// memberIDFromValuePath extracts the user id from a valuePath like `members[value eq "42"]`
// (the Okta/Azure member-removal form). Returns false if it can't be parsed.
func memberIDFromValuePath(path string) (uint, bool) {
	l, r := strings.Index(path, "["), strings.LastIndex(path, "]")
	if l < 0 || r <= l {
		return 0, false
	}
	inner := path[l+1 : r] // e.g. value eq "42"
	q1 := strings.Index(inner, `"`)
	if q1 < 0 {
		return 0, false
	}
	q2 := strings.Index(inner[q1+1:], `"`)
	if q2 < 0 {
		return 0, false
	}
	if uid, err := strconv.ParseUint(inner[q1+1:q1+1+q2], 10, 64); err == nil {
		return uint(uid), true
	}
	return 0, false
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
