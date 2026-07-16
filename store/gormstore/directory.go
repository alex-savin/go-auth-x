package gormstore

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the GORM store also satisfies the directory interface.
var _ authx.DirectoryStore = (*Store)(nil)

// --- directory models (groups, membership, api keys) ---

type Group struct {
	ID uint `gorm:"primaryKey"`
	// OrgID scopes the group to an organization (0 = global). Names are unique per (org, name) —
	// two orgs may both have "engineering" alongside a global one. default:0 backfills the column
	// on migration so pre-org rows read as global.
	OrgID       uint   `gorm:"default:0;uniqueIndex:idx_authx_groups_org_name,priority:1"`
	Name        string `gorm:"uniqueIndex:idx_authx_groups_org_name,priority:2"`
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time // gorm auto-updates on save; surfaced as SCIM meta.lastModified
}

func (Group) TableName() string { return "authx_groups" }

type GroupMembership struct {
	ID      uint `gorm:"primaryKey"`
	UserID  uint `gorm:"uniqueIndex:idx_authx_group_member,priority:1;index"`
	GroupID uint `gorm:"uniqueIndex:idx_authx_group_member,priority:2"`
}

func (GroupMembership) TableName() string { return "authx_group_members" }

type APIKey struct {
	ID         uint `gorm:"primaryKey"`
	Name       string
	Prefix     string
	Hash       []byte `gorm:"uniqueIndex"`
	Groups     string // CSV of group names granted to calls made with this key
	Scopes     string // CSV of scopes this key is limited to (empty = unrestricted)
	OrgID      uint   `gorm:"default:0;index"` // 0 = global; else the org this key is bound to
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func (APIKey) TableName() string { return "authx_api_keys" }

// migrateDirectory is called by New to migrate the directory tables.
func (s *Store) migrateDirectory() error {
	if err := s.db.AutoMigrate(&Group{}, &GroupMembership{}, &APIKey{}); err != nil {
		return err
	}
	// Pre-org deployments carry the old GLOBAL unique index on group name; it must go or two orgs
	// could never share a group name (the composite (org_id, name) index is the replacement,
	// created by AutoMigrate above). Best-effort: absent on fresh databases.
	if s.db.Migrator().HasIndex(&Group{}, "idx_authx_groups_name") {
		if err := s.db.Migrator().DropIndex(&Group{}, "idx_authx_groups_name"); err != nil {
			return err
		}
	}
	return nil
}

func toGroup(g *Group) authx.Group {
	orgID := ""
	if g.OrgID != 0 {
		orgID = orgIDString(g.OrgID)
	}
	return authx.Group{ID: g.ID, Name: g.Name, Description: g.Description, OrgID: orgID, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
}

func csvSplit(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func toAPIKeyInfo(k *APIKey) authx.APIKeyInfo {
	orgID := ""
	if k.OrgID != 0 {
		orgID = orgIDString(k.OrgID)
	}
	return authx.APIKeyInfo{
		ID: k.ID, Name: k.Name, Prefix: k.Prefix, Groups: csvSplit(k.Groups), Scopes: csvSplit(k.Scopes),
		ExpiresAt: k.ExpiresAt, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, OrgID: orgID,
	}
}

// --- groups ---

func (s *Store) CreateGroup(name, description string) (*authx.Group, error) {
	g := Group{Name: strings.TrimSpace(name), Description: description, CreatedAt: time.Now()}
	if err := s.db.Create(&g).Error; err != nil {
		return nil, err
	}
	ag := toGroup(&g)
	return &ag, nil
}

// Groups lists the GLOBAL groups only — org-scoped groups are reached through OrgGroups (see
// OrgDirectoryStore), so an org's namespace never leaks into the global verbs.
func (s *Store) Groups() ([]authx.Group, error) {
	var rows []Group
	if err := s.db.Where("org_id = 0").Order("name").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]authx.Group, 0, len(rows))
	for i := range rows {
		out = append(out, toGroup(&rows[i]))
	}
	return out, nil
}

// GroupByName resolves a GLOBAL group; org-scoped names live in their org's namespace
// (OrgGroupByName).
func (s *Store) GroupByName(name string) (*authx.Group, error) {
	var g Group
	if err := s.db.Where("org_id = 0 AND name = ?", strings.TrimSpace(name)).First(&g).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoGroup
		}
		return nil, err
	}
	ag := toGroup(&g)
	return &ag, nil
}

func (s *Store) DeleteGroup(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("group_id = ?", id).Delete(&GroupMembership{}).Error; err != nil {
			return err
		}
		return tx.Delete(&Group{}, id).Error
	})
}

func (s *Store) AddUserToGroup(userID, groupID uint) error {
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&GroupMembership{UserID: userID, GroupID: groupID}).Error
}

func (s *Store) RemoveUserFromGroup(userID, groupID uint) error {
	return s.db.Where("user_id = ? AND group_id = ?", userID, groupID).Delete(&GroupMembership{}).Error
}

func (s *Store) UserGroups(userID uint) ([]authx.Group, error) {
	var rows []Group
	err := s.db.Table("authx_groups").
		Joins("JOIN authx_group_members m ON m.group_id = authx_groups.id").
		Where("m.user_id = ?", userID).Order("authx_groups.name").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]authx.Group, 0, len(rows))
	for i := range rows {
		out = append(out, toGroup(&rows[i]))
	}
	return out, nil
}

func (s *Store) GroupMembers(groupID uint) ([]authx.AuthUser, error) {
	var rows []User
	err := s.db.Table("authx_users").
		Joins("JOIN authx_group_members m ON m.user_id = authx_users.id").
		Where("m.group_id = ?", groupID).Order("authx_users.email").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]authx.AuthUser, 0, len(rows))
	for i := range rows {
		out = append(out, *toAuthUser(&rows[i]))
	}
	return out, nil
}

// --- admin user management ---

func (s *Store) ListUsers() ([]authx.AuthUser, error) {
	var rows []User
	if err := s.db.Order("email").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]authx.AuthUser, 0, len(rows))
	for i := range rows {
		out = append(out, *toAuthUser(&rows[i]))
	}
	return out, nil
}

func (s *Store) UserByID(id uint) (*authx.AuthUser, error) {
	var u User
	if err := s.db.First(&u, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoUser
		}
		return nil, err
	}
	return toAuthUser(&u), nil
}

func (s *Store) SetUserDisabled(userID uint, disabled bool) error {
	return s.db.Model(&User{}).Where("id = ?", userID).Update("disabled", disabled).Error
}

func (s *Store) SetUserBan(userID uint, banned bool, until *time.Time, reason string) error {
	updates := map[string]any{"banned": banned, "banned_until": until, "ban_reason": reason}
	if !banned {
		updates["banned_until"] = nil
		updates["ban_reason"] = ""
	}
	return s.db.Model(&User{}).Where("id = ?", userID).Updates(updates).Error
}

// UpsertExternalUser provisions a directory-sourced user (LDAP/SCIM) via the safe linking rule.
func (s *Store) UpsertExternalUser(sub, email, name string, emailVerified bool) (*authx.AuthUser, error) {
	return s.UpsertUserOnLogin(sub, email, name, emailVerified)
}

// --- api keys ---

func (s *Store) CreateAPIKey(name string, groups, scopes []string, prefix string, hash []byte, expiresAt *time.Time) (*authx.APIKeyInfo, error) {
	k := APIKey{
		Name: name, Prefix: prefix, Hash: hash, Groups: strings.Join(groups, ","), Scopes: strings.Join(scopes, ","),
		ExpiresAt: expiresAt, CreatedAt: time.Now(),
	}
	if err := s.db.Create(&k).Error; err != nil {
		return nil, err
	}
	info := toAPIKeyInfo(&k)
	return &info, nil
}

func (s *Store) APIKeyByHash(hash []byte) (*authx.APIKeyInfo, error) {
	var k APIKey
	if err := s.db.Where("hash = ?", hash).First(&k).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoCredential
		}
		return nil, err
	}
	info := toAPIKeyInfo(&k)
	return &info, nil
}

func (s *Store) ListAPIKeys() ([]authx.APIKeyInfo, error) {
	var rows []APIKey
	if err := s.db.Order("created_at desc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]authx.APIKeyInfo, 0, len(rows))
	for i := range rows {
		out = append(out, toAPIKeyInfo(&rows[i]))
	}
	return out, nil
}

func (s *Store) RevokeAPIKey(id uint) error { return s.db.Delete(&APIKey{}, id).Error }

func (s *Store) TouchAPIKey(id uint) error {
	now := time.Now()
	return s.db.Model(&APIKey{}).Where("id = ?", id).Update("last_used_at", now).Error
}
