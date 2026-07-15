// Package ldapsync syncs users and groups from an LDAP/Active Directory server into an
// authx.DirectoryStore (and the user records behind it). It is a one-way pull: run it on a
// schedule. It is additive — users/groups present in LDAP are upserted; it does not delete or
// disable records that have disappeared from LDAP (that's a deliberate, separate policy choice).
package ldapsync

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
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
}

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
	cfg Config
	dir authx.DirectoryStore
}

// New builds a Syncer. The directory store must be set on your Authenticator too (SetDirectoryStore).
func New(cfg Config, dir authx.DirectoryStore) *Syncer {
	cfg.withDefaults()
	return &Syncer{cfg: cfg, dir: dir}
}

// Result reports what a sync touched.
type Result struct {
	Users         int
	Groups        int
	Memberships   int
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
	conn, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	res := &Result{}
	userByDN := map[string]uint{}  // DN -> userID (for member=DN groups)
	userByUID := map[string]uint{} // uid -> userID (for memberUid groups)

	users, err := conn.SearchWithPaging(ldap.NewSearchRequest(
		s.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.cfg.UserFilter, []string{s.cfg.AttrUID, s.cfg.AttrEmail, s.cfg.AttrName}, nil), ldapPageSize)
	if err != nil {
		return nil, fmt.Errorf("ldap user search: %w", err)
	}
	seen := map[string]bool{} // "ldap:<uid>" subjects present in this run
	for _, e := range users.Entries {
		uid := e.GetAttributeValue(s.cfg.AttrUID)
		email := e.GetAttributeValue(s.cfg.AttrEmail)
		if uid == "" || email == "" {
			continue // a user with no uid/email can't be keyed or linked
		}
		// Mark PRESENCE as soon as a valid uid is read — BEFORE the upsert — so a user who is present in
		// LDAP but whose upsert transiently fails (DB deadlock / connection blip) is NOT then deprovisioned
		// (disabled) as "missing from LDAP". Deprovision must key on absence from the LDAP search, not on
		// whether the write succeeded this run.
		seen["ldap:"+uid] = true
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
			for _, m := range e.GetAttributeValues(s.cfg.AttrGroupMember) {
				uid, ok := resolveMember(m, userByDN, userByUID)
				if !ok {
					continue
				}
				if err := s.dir.AddUserToGroup(uid, g.ID); err != nil {
					res.Errors = append(res.Errors, fmt.Sprintf("group %s member %s: %v", name, m, err))
					continue
				}
				res.Memberships++
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
			for _, u := range all {
				if strings.HasPrefix(u.Sub, "ldap:") && !seen[u.Sub] && !u.Disabled {
					if err := s.dir.SetUserDisabled(u.ID, true); err != nil {
						res.Errors = append(res.Errors, fmt.Sprintf("deprovision %s: %v", u.Sub, err))
						continue
					}
					res.Deprovisioned++
				}
			}
		}
	}
	return res, nil
}

func (s *Syncer) getOrCreateGroup(name string) (*authx.Group, error) {
	g, err := s.dir.GroupByName(name)
	if err == nil {
		return g, nil
	}
	if errors.Is(err, authx.ErrNoGroup) {
		return s.dir.CreateGroup(name, "synced from LDAP")
	}
	return nil, err
}

// resolveMember maps an LDAP group member value (a full DN, or a bare uid for posixGroup) to a user.
// DNs are normalized before comparison so incidental formatting differences (spacing/case) between a
// member= value and the entry's DN don't silently drop members.
func resolveMember(member string, byDN, byUID map[string]uint) (uint, bool) {
	if strings.Contains(member, "=") { // looks like a DN
		if id, ok := byDN[normalizeDN(member)]; ok {
			return id, true
		}
		return 0, false
	}
	id, ok := byUID[member]
	return id, ok
}

// normalizeDN parses a DN and rebuilds a canonical, lower-cased "attr=value,attr=value" form so two
// DNs that differ only in spacing or attribute case compare equal. Falls back to a trimmed
// lower-case of the raw string when the DN can't be parsed.
func normalizeDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	parts := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		for _, av := range rdn.Attributes {
			parts = append(parts, strings.ToLower(av.Type)+"="+strings.ToLower(strings.TrimSpace(av.Value)))
		}
	}
	return strings.Join(parts, ",")
}
