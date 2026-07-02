package scim

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	authx "github.com/alex-savin/go-auth-x"
)

// SCIM ETags (RFC 7644 §3.14). We emit STRONG ETags: the tag is a sha256 over the resource's stable
// STATE fields (not the wire bytes), so identical state → identical tag regardless of serialization —
// a valid strong validator. Strong tags let If-Match (RFC 9110 §13.1.1, strong comparison) work
// correctly for optimistic concurrency, and satisfy If-None-Match (weak comparison) for caching.

func resourceETag(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return `"` + hex.EncodeToString(h[:8]) + `"`
}

func userVersion(u *authx.AuthUser) string {
	return resourceETag("user", toID(u.ID), u.Email, u.Name, strconv.FormatBool(!u.Disabled))
}

func groupVersion(g authx.Group, members []authx.AuthUser) string {
	parts := []string{"group", toID(g.ID), g.Name}
	for _, m := range members {
		parts = append(parts, toID(m.ID))
	}
	return resourceETag(parts...)
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

// ifMatchFails reports whether an If-Match precondition is present and NOT satisfied (→ 412). Per
// RFC 9110 §13.1.1, If-Match uses STRONG comparison: a weak (W/-prefixed) tag never matches, even if
// its opaque value equals ours.
func ifMatchFails(r *http.Request, version string) bool {
	h := r.Header.Get("If-Match")
	if h == "" || h == "*" { // absent, or "*" matches any existing resource
		return false
	}
	return !etagListHasStrong(h, version)
}

// etagListHas compares an ETag header list against version using weak comparison (ignore the W/ flag).
// Used for If-None-Match (RFC 9110 §13.1.2 permits the weak comparator).
func etagListHas(header, version string) bool {
	want := etagCore(version)
	for _, tag := range strings.Split(header, ",") {
		if etagCore(strings.TrimSpace(tag)) == want {
			return true
		}
	}
	return false
}

// etagListHasStrong compares an ETag header list against version using STRONG comparison: a weak tag
// (W/…) in the header never matches. Our emitted tags are always strong.
func etagListHasStrong(header, version string) bool {
	want := etagCore(version)
	for _, tag := range strings.Split(header, ",") {
		tag = strings.TrimSpace(tag)
		if strings.HasPrefix(tag, "W/") { // weak validator can't satisfy strong comparison
			continue
		}
		if etagCore(tag) == want {
			return true
		}
	}
	return false
}

func etagCore(tag string) string {
	return strings.Trim(strings.TrimPrefix(tag, "W/"), `"`)
}
