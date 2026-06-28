// Package ldapsync syncs users and groups from an LDAP/Active Directory server into an
// authx.DirectoryStore (and the user records behind it). It is a one-way pull: run it on a
// schedule. It is additive — users/groups present in LDAP are upserted; it does not delete or
// disable records that have disappeared from LDAP (that's a deliberate, separate policy choice).
package ldapsync

import (
	"crypto/tls"
	"fmt"
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
	conn, err := ldap.DialURL(s.cfg.URL)
	if err != nil {
		return nil, err
	}
	if s.cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: s.cfg.InsecureTLS}); err != nil {
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

	users, err := conn.Search(ldap.NewSearchRequest(
		s.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.cfg.UserFilter, []string{s.cfg.AttrUID, s.cfg.AttrEmail, s.cfg.AttrName}, nil))
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
		au, uerr := s.dir.UpsertExternalUser("ldap:"+uid, email, e.GetAttributeValue(s.cfg.AttrName), true)
		if uerr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("user %s: %v", uid, uerr))
			continue
		}
		userByDN[strings.ToLower(e.DN)] = au.ID
		userByUID[uid] = au.ID
		seen["ldap:"+uid] = true
		res.Users++
	}

	if s.cfg.GroupBaseDN != "" {
		groups, gerr := conn.Search(ldap.NewSearchRequest(
			s.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			s.cfg.GroupFilter, []string{s.cfg.AttrGroupName, s.cfg.AttrGroupMember}, nil))
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
				if err := s.dir.AddUserToGroup(uid, g.ID); err == nil {
					res.Memberships++
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
			for _, u := range all {
				if strings.HasPrefix(u.Sub, "ldap:") && !seen[u.Sub] && !u.Disabled {
					if err := s.dir.SetUserDisabled(u.ID, true); err == nil {
						res.Deprovisioned++
					}
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
	if err == authx.ErrNoGroup {
		return s.dir.CreateGroup(name, "synced from LDAP")
	}
	return nil, err
}

// resolveMember maps an LDAP group member value (a full DN, or a bare uid for posixGroup) to a user.
func resolveMember(member string, byDN, byUID map[string]uint) (uint, bool) {
	if strings.Contains(member, "=") { // looks like a DN
		if id, ok := byDN[strings.ToLower(member)]; ok {
			return id, true
		}
		return 0, false
	}
	id, ok := byUID[member]
	return id, ok
}
