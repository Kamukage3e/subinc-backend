package organization_management

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// OrganizationService
func (s *PostgresStore) CreateOrganization(ctx context.Context, org Organization) (Organization, error) {
	const q = `INSERT INTO organizations (id, name, slug, owner_id, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, slug, owner_id, status, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.DB.QueryRow(ctx, q, id, org.Name, org.Slug, org.OwnerID, org.Status, now, now)
	var out Organization
	if err := row.Scan(&out.ID, &out.Name, &out.Slug, &out.OwnerID, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("CreateOrganization failed", logger.ErrorField(err), logger.Any("org", org))
		return Organization{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateOrganization(ctx context.Context, org Organization) (Organization, error) {
	const q = `UPDATE organizations SET name = $2, slug = $3, owner_id = $4, status = $5, updated_at = $6 WHERE id = $1 RETURNING id, name, slug, owner_id, status, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, org.ID, org.Name, org.Slug, org.OwnerID, org.Status, time.Now().UTC())
	var out Organization
	if err := row.Scan(&out.ID, &out.Name, &out.Slug, &out.OwnerID, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("UpdateOrganization failed", logger.ErrorField(err), logger.Any("org", org))
		return Organization{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteOrganization(ctx context.Context, id string) error {
	const q = `DELETE FROM organizations WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteOrganization failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) GetOrganization(ctx context.Context, id string) (Organization, error) {
	const q = `SELECT id, name, slug, owner_id, status, created_at, updated_at FROM organizations WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Organization
	if err := row.Scan(&out.ID, &out.Name, &out.Slug, &out.OwnerID, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("GetOrganization failed", logger.ErrorField(err), logger.String("id", id))
		return Organization{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListOrganizations(ctx context.Context, ownerID string, page, pageSize int) ([]Organization, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, name, slug, owner_id, status, created_at, updated_at FROM organizations WHERE owner_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, q, ownerID, pageSize, offset)
	if err != nil {
		logger.LogError("ListOrganizations query failed", logger.ErrorField(err), logger.String("owner_id", ownerID))
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
			logger.LogError("ListOrganizations scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// OrgDomainService
func (s *PostgresStore) AddDomain(ctx context.Context, domain OrgDomain) (OrgDomain, error) {
	const q = `INSERT INTO org_domains (id, org_id, domain, verified, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, org_id, domain, verified, created_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.DB.QueryRow(ctx, q, id, domain.OrgID, domain.Domain, domain.Verified, now)
	var out OrgDomain
	if err := row.Scan(&out.ID, &out.OrgID, &out.Domain, &out.Verified, &out.CreatedAt); err != nil {
		logger.LogError("AddDomain failed", logger.ErrorField(err), logger.Any("domain", domain))
		return OrgDomain{}, err
	}
	return out, nil
}

func (s *PostgresStore) VerifyDomain(ctx context.Context, id string) error {
	const q = `UPDATE org_domains SET verified = true WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("VerifyDomain failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) RemoveDomain(ctx context.Context, id string) error {
	const q = `DELETE FROM org_domains WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("RemoveDomain failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) ListDomains(ctx context.Context, orgID string) ([]OrgDomain, error) {
	const q = `SELECT id, org_id, domain, verified, created_at FROM org_domains WHERE org_id = $1 ORDER BY created_at DESC`
	rows, err := s.DB.Query(ctx, q, orgID)
	if err != nil {
		logger.LogError("ListDomains query failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return nil, err
	}
	defer rows.Close()
	var out []OrgDomain
	for rows.Next() {
		var d OrgDomain
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Domain, &d.Verified, &d.CreatedAt); err != nil {
			logger.LogError("ListDomains scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// OrgSettingsService
func (s *PostgresStore) GetSettings(ctx context.Context, orgID string) (map[string]interface{}, error) {
	if orgID == "" {
		logger.LogError("org id required")
		return nil, errors.New("org id required")
	}
	key := "org_settings_" + orgID
	cfg, err := s.ServerConfigService.Get(ctx, key)
	if err != nil {
		if err.Error() == "config not found" {
			return map[string]interface{}{}, nil
		}
		logger.LogError("failed to get org settings", logger.ErrorField(err), logger.String("org_id", orgID))
		return nil, err
	}
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.Value), &settings); err != nil {
		logger.LogError("invalid org settings json", logger.ErrorField(err), logger.String("org_id", orgID))
		return nil, errors.New("invalid org settings json")
	}
	return settings, nil
}

func (s *PostgresStore) UpdateSettings(ctx context.Context, orgID string, settings map[string]interface{}) error {
	if orgID == "" {
		logger.LogError("org id required")
		return errors.New("org id required")
	}
	key := "org_settings_" + orgID
	b, err := json.Marshal(settings)
	if err != nil {
		logger.LogError("marshal org settings failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return errors.New("invalid org settings")
	}
	_, err = s.ServerConfigService.Set(ctx, key, string(b), "system")
	if err != nil {
		logger.LogError("failed to set org settings", logger.ErrorField(err), logger.String("org_id", orgID))
		return err
	}
	return nil
}
