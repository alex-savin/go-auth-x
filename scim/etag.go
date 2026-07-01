package scim

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	authx "github.com/alex-savin/go-auth-x"
)

// SCIM ETags (RFC 7644 §3.14). We emit WEAK ETags derived from a resource's content fingerprint —
// the directory doesn't store a monotonic version, so the ETag changes whenever the representation
// changes. Enough for optimistic concurrency (If-Match on writes) and caching (If-None-Match on GET).

func weakETag(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return `W/"` + hex.EncodeToString(h[:8]) + `"`
}

func userVersion(u *authx.AuthUser) string {
	return weakETag("user", toID(u.ID), u.Email, u.Name, strconv.FormatBool(!u.Disabled))
}

func groupVersion(g authx.Group, members []authx.AuthUser) string {
	parts := []string{"group", toID(g.ID), g.Name}
	for _, m := range members {
		parts = append(parts, toID(m.ID))
	}
	return weakETag(parts...)
}

// writeResource writes a single resource with its ETag header.
func writeResource(w http.ResponseWriter, code int, obj any, version string) {
	if version != "" {
		w.Header().Set("ETag", version)
	}
	writeSCIM(w, code, obj)
}

// ifNoneMatchSatisfied reports whether an If-None-Match precondition matches (caller returns 304).
func ifNoneMatchSatisfied(r *http.Request, version string) bool {
	h := r.Header.Get("If-None-Match")
	return h != "" && (h == "*" || etagListHas(h, version))
}

// ifMatchFails reports whether an If-Match precondition is present and NOT satisfied (→ 412).
func ifMatchFails(r *http.Request, version string) bool {
	h := r.Header.Get("If-Match")
	if h == "" || h == "*" { // absent, or "*" matches any existing resource
		return false
	}
	return !etagListHas(h, version)
}

// etagListHas compares an ETag header list against version using weak comparison (ignore the W/ flag).
func etagListHas(header, version string) bool {
	want := etagCore(version)
	for _, tag := range strings.Split(header, ",") {
		if etagCore(strings.TrimSpace(tag)) == want {
			return true
		}
	}
	return false
}

func etagCore(tag string) string {
	return strings.Trim(strings.TrimPrefix(tag, "W/"), `"`)
}
