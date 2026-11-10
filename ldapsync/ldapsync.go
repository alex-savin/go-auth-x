// Package ldapsync syncs users and groups from an LDAP/Active Directory server into an
// authx.DirectoryStore (and the user records behind it). It is a one-way pull: run it on a
// schedule. Users and groups present in LDAP are upserted, and a synced user's group memberships
// follow the directory: one LDAP no longer lists is removed (Config.KeepStaleMemberships keeps
// them). It never deletes users or groups; disabling users that left LDAP is opt-in
// (Config.DeprovisionMissing).
package ldapsync

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	authx "github.com/alex-savin/go-auth-x"
)

// Config describes the LDAP connection + the attribute mapping. Sensible OpenLDAP defaults are
// filled in by New; for Active Directory set AttrUID="sAMAccountName" and GroupFilter/member to AD.
type Config struct {
	URL          string // ldap://host:389 or ldaps://host:636
	BindDN       string // service-account DN (empty = anonymous bind)
	BindPassword string
	StartTLS     bool
	InsecureTLS  bool // skip cert verification (dev only)

	UserBaseDN string
	UserFilter string // default: (objectClass=person)
	AttrUID    string // default: uid
	AttrEmail  string // default: mail
	AttrName   string // default: cn

	GroupBaseDN     string
	GroupFilter     string // default: (objectClass=groupOfNames)
	AttrGroupName   string // default: cn
	AttrGroupMember string // default: member (DN values) — use memberUid for posixGroup

	// DeprovisionMissing disables (does not delete) any previously-synced "ldap:" user that was
	// NOT seen in this run — i.e. they vanished from LDAP. Off by default (additive sync).
	DeprovisionMissing bool

	// AdoptExisting lets an LDAP entry take over an existing account with the same email — a local
	// password account, an OIDC or social sign-in — rebinding it to the LDAP subject (an unverified one
	// is replaced). Off by default: such an entry is skipped and reported, because whoever can set an
	// entry's mail attribute would otherwise take the account (and the owner's). Turn it on only for a
	// directory you trust as much as your own sign-in.
	AdoptExisting bool

	// KeepStaleMemberships turns off the removal of group memberships LDAP no longer lists. By default
	// a synced ("ldap:") user who was removed from an LDAP group — or whose group left the directory —
	// loses that membership on the next sync, so access a group gates ends when the directory says
	// so. Members that aren't LDAP users (added by an operator, SCIM, …) are never removed.
	KeepStaleMemberships bool

	// OwnGroupsOnly makes the sync leave alone any existing group it didn't create: an LDAP group
	// with the name of an operator-made one (say "admins") is skipped and reported instead of having
	// its members merged in. Off by default (an LDAP group adopts a same-named group).
	OwnGroupsOnly bool

	// MaxDeprovision caps how many users one run may disable with DeprovisionMissing (0 = no cap).
	// A run that would disable more — a search that came back partial after an ACL or filter
	// change — disables none and reports it.
	MaxDeprovision int
}

// groupMarker is the description of a group the sync created: how it knows its own groups.
const groupMarker = "synced from LDAP"

func (c *Config) withDefaults() {
	if c.UserFilter == "" {
		c.UserFilter = "(objectClass=person)"
	}
	if c.AttrUID == "" {
		c.AttrUID = "uid"
	}
	if c.AttrEmail == "" {
		c.AttrEmail = "mail"
	}
	if c.AttrName == "" {
		c.AttrName = "cn"
	}
	if c.GroupFilter == "" {
		c.GroupFilter = "(objectClass=groupOfNames)"
	}
	if c.AttrGroupName == "" {
		c.AttrGroupName = "cn"
	}
	if c.AttrGroupMember == "" {
		c.AttrGroupMember = "member"
	}
}

// ldapPageSize bounds each LDAP page so the sync works against directories larger than the server's
// max result-size limit (Active Directory defaults to 1000) instead of failing/truncating.
const ldapPageSize = 500

// Syncer pulls from LDAP into a directory.
type Syncer struct {
	cfg     Config
	dir     authx.DirectoryStore
	connect func() (searcher, error) // dial by default; tests substitute a fake directory
}

// searcher is what Sync needs of an LDAP connection (*ldap.Conn has it).
type searcher interface {
	SearchWithPaging(req *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)
	Close() error
}

// New builds a Syncer. The directory store must be set on your Authenticator too (SetDirectoryStore).
func New(cfg Config, dir authx.DirectoryStore) *Syncer {
	cfg.withDefaults()
	s := &Syncer{cfg: cfg, dir: dir}
	s.connect = func() (searcher, error) { return s.dial() }
	return s
}

// Result reports what a sync touched.
type Result struct {
	Users         int
	Groups        int
	Memberships   int
	Removed       int // memberships of "ldap:" users removed because LDAP no longer lists them
	Deprovisioned int // "ldap:" users disabled because they vanished from LDAP (if enabled)
	Errors        []string
}

func (s *Syncer) dial() (*ldap.Conn, error) {
	u, uerr := url.Parse(s.cfg.URL)
	if uerr != nil {
		return nil, fmt.Errorf("ldap: invalid URL %q: %w", s.cfg.URL, uerr)
	}
	ldaps := strings.EqualFold(u.Scheme, "ldaps")
	// Never send a bind password over an unprotected channel (RFC 4513 §5.1.3): require StartTLS or
	// ldaps:// whenever an authenticated bind is configured.
	if s.cfg.BindPassword != "" && !s.cfg.StartTLS && !ldaps {
		return nil, errors.New("ldap: refusing to send a bind password over cleartext — enable StartTLS or use ldaps://")
	}
	var opts []ldap.DialOpt
	if ldaps {
		// For ldaps:// the TLS handshake happens in DialURL, so InsecureTLS/ServerName must be passed
		// here — otherwise InsecureTLS is silently ignored and a self-signed dev cert fails.
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: s.cfg.InsecureTLS}))
	}
	conn, err := ldap.DialURL(s.cfg.URL, opts...)
	if err != nil {
		return nil, err
	}
	if s.cfg.StartTLS {
		// ServerName is required for hostname verification (RFC 4513 §3.1.3); without it the secure
		// default fails on real certs, pushing operators to disable verification (a MITM footgun).
		if err := conn.StartTLS(&tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: s.cfg.InsecureTLS}); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if s.cfg.BindDN != "" {
		if err := conn.Bind(s.cfg.BindDN, s.cfg.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap bind: %w", err)
		}
	}
	return conn, nil
}

// Sync connects, pulls users then groups, and upserts them into the directory.
func (s *Syncer) Sync() (*Result, error) {
	conn, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res := &Result{}
	userByDN := map[string]string{}  // DN -> userID (for member=DN groups)
	userByUID := map[string]string{} // uid -> userID (for memberUid groups)

	users, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		s.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.cfg.UserFilter, []string{s.cfg.AttrUID, s.cfg.AttrEmail, s.cfg.AttrName}, nil), ldapPageSize)
	if err != nil {
		return nil, fmt.Errorf("ldap user search: %w", err)
	}
	seen := map[string]bool{} // "ldap:<uid>" subjects present in this run
	// A uid on more than one entry names no one: whichever entry came last would own the account —
	// its groups, its sessions' identity — and its mail. An entry that can set its own uid attribute
	// to someone else's would take their account that way, so none of the entries is synced.
	entriesPerUID := map[string]int{}
	for _, e := range users.Entries {
		if uid := e.GetAttributeValue(s.cfg.AttrUID); uid != "" {
			entriesPerUID[uid]++
		}
	}
	reported := map[string]bool{}
	for _, e := range users.Entries {
		uid := e.GetAttributeValue(s.cfg.AttrUID)
		email := e.GetAttributeValue(s.cfg.AttrEmail)
		if uid == "" || email == "" {
			continue // a user with no uid/email can't be keyed or linked
		}
		if entriesPerUID[uid] > 1 {
			seen["ldap:"+uid] = true // present, if ambiguous: not "missing from LDAP"
			if !reported[uid] {
				reported[uid] = true
				res.Errors = append(res.Errors, fmt.Sprintf("user %s: %d entries share this %s; none synced (use an attribute that is unique and that entries can't set themselves, e.g. entryUUID or objectGUID)", uid, entriesPerUID[uid], s.cfg.AttrUID))
			}
			continue
		}
		// Mark PRESENCE as soon as a valid uid is read — BEFORE the upsert — so a user who is present in
		// LDAP but whose upsert transiently fails (DB deadlock / connection blip) is NOT then deprovisioned
		// (disabled) as "missing from LDAP". Deprovision must key on absence from the LDAP search, not on
		// whether the write succeeded this run.
		seen["ldap:"+uid] = true
		if !s.cfg.AdoptExisting {
			if existing, xerr := s.dir.UserByEmail(email); xerr == nil && existing.Sub != "ldap:"+uid {
				res.Errors = append(res.Errors, fmt.Sprintf("user %s: %s belongs to an account not synced from this entry; skipped (see Config.AdoptExisting)", uid, email))
				continue
			}
		}
		au, uerr := s.dir.UpsertExternalUser("ldap:"+uid, email, e.GetAttributeValue(s.cfg.AttrName), true)
		if uerr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("user %s: %v", uid, uerr))
			continue
		}
		userByDN[normalizeDN(e.DN)] = au.ID
		userByUID[uid] = au.ID
		res.Users++
	}

	if s.cfg.GroupBaseDN != "" {
		groups, gerr := conn.SearchWithPaging(ldap.NewSearchRequest(
			s.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			s.cfg.GroupFilter, []string{s.cfg.AttrGroupName, s.cfg.AttrGroupMember}, nil), ldapPageSize)
		if gerr != nil {
			return res, fmt.Errorf("ldap group search: %w", gerr)
		}
		// Memberships LDAP no longer lists are removed — unless nothing came back to compare with
		// (no users, or no groups: a mis-set base or filter must not strip every membership).
		prune := !s.cfg.KeepStaleMemberships && res.Users > 0 && len(groups.Entries) > 0
		synced := map[string]bool{} // ids of the groups present in this run
		for _, e := range groups.Entries {
			name := e.GetAttributeValue(s.cfg.AttrGroupName)
			if name == "" {
				continue
			}
			g, cerr := s.getOrCreateGroup(name)
			if cerr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("group %s: %v", name, cerr))
				continue
			}
			res.Groups++
			synced[g.ID] = true
			listed := map[string]bool{}
			for _, m := range e.GetAttributeValues(s.cfg.AttrGroupMember) {
				uid, ok := resolveMember(m, userByDN, userByUID)
				if !ok {
					continue
				}
				listed[uid] = true
				if err := s.dir.AddUserToGroup(uid, g.ID); err != nil {
					res.Errors = append(res.Errors, fmt.Sprintf("group %s member %s: %v", name, m, err))
					continue
				}
				res.Memberships++
			}
			if prune {
				s.pruneMembers(res, *g, listed)
			}
		}
		if prune {
			// A group the sync made that LDAP no longer has: its LDAP members leave it.
			if all, lerr := s.dir.Groups(); lerr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("stale groups: %v", lerr))
			} else {
				for _, g := range all {
					if g.Description == groupMarker && !synced[g.ID] {
						s.pruneMembers(res, g, nil)
					}
				}
			}
		}
	}

	// Deprovision: disable any previously-synced LDAP user that wasn't seen this run.
	// SAFETY GUARD: if zero users were synced (a mis-set base DN/filter, an empty page, or a
	// replication blip), refuse to deprovision — otherwise a transient empty result would disable
	// every ldap: user at once. Bounded anyway (disable, never delete), but fail safe.
	if s.cfg.DeprovisionMissing && res.Users == 0 {
		res.Errors = append(res.Errors, "deprovision skipped: user search returned 0 entries")
	} else if s.cfg.DeprovisionMissing {
		all, lerr := s.dir.ListUsers()
		if lerr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("deprovision list: %v", lerr))
		} else {
			var missing []authx.AuthUser
			for _, u := range all {
				if strings.HasPrefix(u.Sub, "ldap:") && !seen[u.Sub] && !u.Disabled {
					missing = append(missing, u)
				}
			}
			if s.cfg.MaxDeprovision > 0 && len(missing) > s.cfg.MaxDeprovision {
				res.Errors = append(res.Errors, fmt.Sprintf("deprovision skipped: %d users are missing from the search, more than MaxDeprovision (%d)", len(missing), s.cfg.MaxDeprovision))
				missing = nil
			}
			for _, u := range missing {
				if err := s.dir.SetUserDisabled(u.ID, true); err != nil {
					res.Errors = append(res.Errors, fmt.Sprintf("deprovision %s: %v", u.Sub, err))
					continue
				}
				res.Deprovisioned++
			}
		}
	}
	return res, nil
}

func (s *Syncer) getOrCreateGroup(name string) (*authx.Group, error) {
	g, err := s.dir.GroupByName(name)
	if err == nil {
		if s.cfg.OwnGroupsOnly && g.Description != groupMarker {
			return nil, errors.New("a group with this name exists that the sync didn't create; skipped (see Config.OwnGroupsOnly)")
		}
		return g, nil
	}
	if errors.Is(err, authx.ErrNoGroup) {
		return s.dir.CreateGroup(name, groupMarker)
	}
	return nil, err
}

// pruneMembers removes from g the LDAP users ("ldap:" subjects) that listed doesn't hold. Members
// from elsewhere — an operator's, SCIM's — are not the sync's to remove.
func (s *Syncer) pruneMembers(res *Result, g authx.Group, listed map[string]bool) {
	members, err := s.dir.GroupMembers(g.ID)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("group %s members: %v", g.Name, err))
		return
	}
	for _, m := range members {
		if listed[m.ID] || !strings.HasPrefix(m.Sub, "ldap:") {
			continue
		}
		if err := s.dir.RemoveUserFromGroup(m.ID, g.ID); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("group %s: removing %s: %v", g.Name, m.Sub, err))
			continue
		}
		res.Removed++
	}
}

// resolveMember maps an LDAP group member value (a full DN, or a bare uid for posixGroup) to a user.
// DNs are normalized before comparison so incidental formatting differences (spacing/case) between a
// member= value and the entry's DN don't silently drop members.
func resolveMember(member string, byDN, byUID map[string]string) (string, bool) {
	if strings.Contains(member, "=") { // looks like a DN
		if id, ok := byDN[normalizeDN(member)]; ok {
			return id, true
		}
		return "", false
	}
	id, ok := byUID[member]
	return id, ok
}

// normalizeDN parses a DN and rebuilds a canonical, lower-cased form so two DNs that differ only in
// spacing, attribute case or the order of a multi-valued RDN's parts compare equal — and only those:
// the separators inside a value stay escaped, so "cn=a\,ou\=b,dc=x" (one RDN whose value holds a
// comma) is not "cn=a,ou=b,dc=x" (two RDNs). Rebuilt unescaped, an entry could be named so that it
// normalized to another user's DN and received their group memberships. Falls back to a trimmed
// lower-case of the raw string when the DN can't be parsed.
func normalizeDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	esc := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `+`, `\+`, `=`, `\=`)
	rdns := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		avs := make([]string, 0, len(rdn.Attributes))
		for _, av := range rdn.Attributes {
			avs = append(avs, strings.ToLower(av.Type)+"="+esc.Replace(strings.ToLower(strings.TrimSpace(av.Value))))
		}
		sort.Strings(avs)
		rdns = append(rdns, strings.Join(avs, "+"))
	}
	return strings.Join(rdns, ",")
}
