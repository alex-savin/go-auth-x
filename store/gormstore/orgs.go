package gormstore

import (
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"

	authx "github.com/alex-savin/go-auth-x"
)

// compile-time proof the GORM store also satisfies the org interface.
var _ authx.OrgStore = (*Store)(nil)

// --- org models ---

// Org keeps the reference store's numeric PK; the public authx.Org.ID is its decimal string form,
// converted at this boundary (the opaque-string-ID shape of roadmap #2 — no uuid migration needed).
type Org struct {
	ID        uint   `gorm:"primaryKey"`
	Slug      string `gorm:"uniqueIndex"`
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Org) TableName() string { return "authx_orgs" }

type OrgMembership struct {
	ID        uint `gorm:"primaryKey"`
	OrgID     uint `gorm:"uniqueIndex:idx_authx_org_member,priority:1"`
	UserID    uint `gorm:"uniqueIndex:idx_authx_org_member,priority:2;index"`
	Role      string
	CreatedAt time.Time
}

func (OrgMembership) TableName() string { return "authx_org_members" }

// migrateOrgs is called by New to migrate the org tables.
func (s *Store) migrateOrgs() error {
	return s.db.AutoMigrate(&Org{}, &OrgMembership{})
}

func orgIDString(id uint) string { return strconv.FormatUint(uint64(id), 10) }

// parseOrgID maps the opaque ID back to the PK; a malformed/zero ID is an ID that cannot exist,
// so callers treat !ok as ErrNoOrg.
func parseOrgID(s string) (uint, bool) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint(n), true
}

func toOrg(o *Org) authx.Org {
	return authx.Org{ID: orgIDString(o.ID), Slug: o.Slug, Name: o.Name, CreatedAt: o.CreatedAt, UpdatedAt: o.UpdatedAt}
}

// --- orgs ---

func (s *Store) CreateOrg(slug, name string) (*authx.Org, error) {
	o := Org{Slug: slug, Name: name, CreatedAt: time.Now()}
	if err := s.db.Create(&o).Error; err != nil {
		return nil, err
	}
	ao := toOrg(&o)
	return &ao, nil
}

func (s *Store) OrgByID(id string) (*authx.Org, error) {
	n, ok := parseOrgID(id)
	if !ok {
		return nil, authx.ErrNoOrg
	}
	var o Org
	if err := s.db.First(&o, n).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoOrg
		}
		return nil, err
	}
	ao := toOrg(&o)
	return &ao, nil
}

func (s *Store) OrgBySlug(slug string) (*authx.Org, error) {
	var o Org
	if err := s.db.Where("slug = ?", slug).First(&o).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, authx.ErrNoOrg
		}
		return nil, err
	}
	ao := toOrg(&o)
	return &ao, nil
}

func (s *Store) Orgs() ([]authx.Org, error) {
	var rows []Org
	if err := s.db.Order("slug").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]authx.Org, 0, len(rows))
	for i := range rows {
		out = append(out, toOrg(&rows[i]))
	}
	return out, nil
}

// orgExists reports whether the org row exists, on the given handle so tx callers compose. The
// single existence probe behind OrgRole / OrgMembers / SetOrgMember.
func orgExists(db *gorm.DB, n uint) (bool, error) {
	var count int64
	if err := db.Model(&Org{}).Where("id = ?", n).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) RenameOrg(id, name string) error {
	n, ok := parseOrgID(id)
	if !ok {
		return authx.ErrNoOrg
	}
	// Existence is probed explicitly rather than inferred from the UPDATE's RowsAffected — MySQL
	// reports 0 affected rows for a same-value update, which would misread a no-op rename as
	// ErrNoOrg (SQLite/Postgres count matched rows and don't have this hazard).
	ok, err := orgExists(s.db, n)
	if err != nil {
		return err
	}
	if !ok {
		return authx.ErrNoOrg
	}
	return s.db.Model(&Org{}).Where("id = ?", n).Update("name", name).Error
}

func (s *Store) DeleteOrg(id string) error {
	n, ok := parseOrgID(id)
	if !ok {
		return nil // idempotent: an ID that can't exist is already gone
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("org_id = ?", n).Delete(&OrgMembership{}).Error; err != nil {
			return err
		}
		return tx.Delete(&Org{}, n).Error
	})
}

// --- membership ---

func (s *Store) SetOrgMember(orgID string, userID uint, role string) error {
	n, ok := parseOrgID(orgID)
	if !ok {
		return authx.ErrNoOrg
	}
	// Select-then-write rather than a composite-key ON CONFLICT (which does not resolve uniformly
	// across drivers) or an UPDATE-RowsAffected probe (MySQL reports 0 for a same-value update,
	// which would misroute an idempotent re-set into Create and trip the unique index). The unique
	// index stays the fail-closed backstop under a create race.
	return s.db.Transaction(func(tx *gorm.DB) error {
		if ok, err := orgExists(tx, n); err != nil {
			return err
		} else if !ok {
			return authx.ErrNoOrg
		}
		// Refuse a membership for a nonexistent user — a dangling row would be invisible in
		// OrgMembers yet inherited (role and all) by the future user assigned this ID.
		var users int64
		if err := tx.Model(&User{}).Where("id = ?", userID).Count(&users).Error; err != nil {
			return err
		}
		if users == 0 {
			return authx.ErrNoUser
		}
		var m OrgMembership
		err := tx.Where("org_id = ? AND user_id = ?", n, userID).First(&m).Error
		switch {
		case err == nil:
			return tx.Model(&OrgMembership{}).Where("id = ?", m.ID).Update("role", role).Error
		case errors.Is(err, gorm.ErrRecordNotFound):
			return tx.Create(&OrgMembership{OrgID: n, UserID: userID, Role: role, CreatedAt: time.Now()}).Error
		default:
			return err
		}
	})
}

func (s *Store) RemoveOrgMember(orgID string, userID uint) error {
	n, ok := parseOrgID(orgID)
	if !ok {
		return nil
	}
	return s.db.Where("org_id = ? AND user_id = ?", n, userID).Delete(&OrgMembership{}).Error
}

func (s *Store) OrgRole(orgID string, userID uint) (string, error) {
	n, ok := parseOrgID(orgID)
	if !ok {
		return "", authx.ErrNoOrg
	}
	var m OrgMembership
	err := s.db.Where("org_id = ? AND user_id = ?", n, userID).First(&m).Error
	if err == nil {
		return m.Role, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", err
	}
	// Distinguish "org absent" from "not a member" only on the miss path (no cost when present).
	if ok, cerr := orgExists(s.db, n); cerr != nil {
		return "", cerr
	} else if !ok {
		return "", authx.ErrNoOrg
	}
	return "", authx.ErrNotOrgMember
}

func (s *Store) UserOrgs(userID uint) ([]authx.UserOrg, error) {
	var rows []struct {
		ID        uint
		Slug      string
		Name      string
		CreatedAt time.Time
		UpdatedAt time.Time
		Role      string
	}
	err := s.db.Table("authx_orgs").
		Select("authx_orgs.id, authx_orgs.slug, authx_orgs.name, authx_orgs.created_at, authx_orgs.updated_at, m.role").
		Joins("JOIN authx_org_members m ON m.org_id = authx_orgs.id").
		Where("m.user_id = ?", userID).Order("authx_orgs.slug").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]authx.UserOrg, 0, len(rows))
	for _, r := range rows {
		out = append(out, authx.UserOrg{
			Org:  authx.Org{ID: orgIDString(r.ID), Slug: r.Slug, Name: r.Name, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt},
			Role: r.Role,
		})
	}
	return out, nil
}

func (s *Store) OrgMembers(orgID string) ([]authx.OrgMember, error) {
	n, ok := parseOrgID(orgID)
	if !ok {
		return nil, authx.ErrNoOrg
	}
	if ok, err := orgExists(s.db, n); err != nil {
		return nil, err
	} else if !ok {
		return nil, authx.ErrNoOrg
	}
	// Two indexed queries + a map join (reuses toAuthUser) instead of scanning a hand-built
	// user+role projection.
	var ms []OrgMembership
	if err := s.db.Where("org_id = ?", n).Find(&ms).Error; err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return []authx.OrgMember{}, nil
	}
	ids := make([]uint, 0, len(ms))
	for i := range ms {
		ids = append(ids, ms[i].UserID)
	}
	var us []User
	if err := s.db.Where("id IN ?", ids).Order("email").Find(&us).Error; err != nil {
		return nil, err
	}
	roleOf := make(map[uint]string, len(ms))
	for i := range ms {
		roleOf[ms[i].UserID] = ms[i].Role
	}
	out := make([]authx.OrgMember, 0, len(us))
	for i := range us {
		out = append(out, authx.OrgMember{User: *toAuthUser(&us[i]), Role: roleOf[us[i].ID]})
	}
	return out, nil
}
