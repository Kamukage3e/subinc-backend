package tenant_management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewTenantSettingsStore(db *pgxpool.Pool, log *logger.Logger) *TenantSettingsStore {
	return &TenantSettingsStore{DB: db, log: log}
}

// GetTenantSettings fetches settings JSON for a tenant by id
func (s *TenantSettingsStore) GetTenantSettings(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	if tenantID == "" {
		s.log.Error("tenant id required")
		return nil, errors.New("tenant id required")
	}
	const q = `SELECT settings FROM tenants WHERE id = $1`
	var settingsStr string
	row := s.DB.QueryRow(ctx, q, tenantID)
	err := row.Scan(&settingsStr)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			s.log.Error("tenant not found", logger.String("tenant_id", tenantID))
			return nil, errors.New("tenant not found")
		}
		s.log.Error("failed to get tenant settings", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	if settingsStr == "" {
		return map[string]interface{}{}, nil
	}
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(settingsStr), &settings); err != nil {
		s.log.Error("invalid settings JSON", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, errors.New("invalid settings JSON")
	}
	return settings, nil
}

// UpdateTenantSettings updates the settings JSON for a tenant by id
func (s *TenantSettingsStore) UpdateTenantSettings(ctx context.Context, tenantID string, input map[string]interface{}) (map[string]interface{}, error) {
	if tenantID == "" {
		s.log.Error("tenant id required")
		return nil, errors.New("tenant id required")
	}
	settingsBytes, err := json.Marshal(input)
	if err != nil {
		s.log.Error("invalid settings input", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, errors.New("invalid settings input")
	}
	const q = `UPDATE tenants SET settings = $1, updated_at = $2 WHERE id = $3`
	res, err := s.DB.Exec(ctx, q, string(settingsBytes), time.Now().UTC(), tenantID)
	if err != nil {
		s.log.Error("failed to update tenant settings", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	if res.RowsAffected() == 0 {
		s.log.Error("tenant not found", logger.String("tenant_id", tenantID))
		return nil, errors.New("tenant not found")
	}
	return input, nil
}

type TenantStore struct {
	DB  *pgxpool.Pool
	log *logger.Logger
}

func NewTenantStore(db *pgxpool.Pool, log *logger.Logger) *TenantStore {
	return &TenantStore{DB: db, log: log}
}

func (s *TenantStore) CreateTenant(ctx context.Context, tenant *Tenant) error {
	if tenant.ID == "" {
		tenant.ID = uuid.NewString()
	}
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = time.Now().UTC()
	}
	if tenant.UpdatedAt.IsZero() {
		tenant.UpdatedAt = tenant.CreatedAt
	}
	const q = `INSERT INTO tenants (id, name, settings, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.DB.Exec(ctx, q, tenant.ID, tenant.Name, tenant.Settings, tenant.CreatedAt, tenant.UpdatedAt)
	if err != nil {
		s.log.Error("failed to create tenant", logger.ErrorField(err), logger.String("id", tenant.ID), logger.String("name", tenant.Name))
		return errors.New("failed to create tenant: " + err.Error())
	}
	return nil
}

func (s *TenantStore) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	tenant.UpdatedAt = time.Now().UTC()
	const q = `UPDATE tenants SET name = $2, settings = $3, updated_at = $4 WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, tenant.ID, tenant.Name, tenant.Settings, tenant.UpdatedAt)
	if err != nil {
		s.log.Error("failed to update tenant", logger.ErrorField(err), logger.String("id", tenant.ID), logger.String("name", tenant.Name))
		return errors.New("failed to update tenant: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		s.log.Error("tenant not found", logger.String("id", tenant.ID))
		return errors.New("tenant not found")
	}
	return nil
}

func (s *TenantStore) DeleteTenant(ctx context.Context, id string) error {
	const q = `DELETE FROM tenants WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		s.log.Error("failed to delete tenant", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete tenant: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		s.log.Error("tenant not found", logger.String("id", id))
		return errors.New("tenant not found")
	}
	return nil
}

func (s *TenantStore) ListTenants(ctx context.Context) ([]interface{}, error) {
	const q = `SELECT id, name, settings, created_at, updated_at FROM tenants`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		s.log.Error("failed to query tenants", logger.ErrorField(err))
		return nil, errors.New("failed to query tenants")
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Settings, &t.CreatedAt, &t.UpdatedAt); err != nil {
			s.log.Error("failed to scan tenant row", logger.ErrorField(err))
			return nil, errors.New("failed to scan tenant row")
		}
		tenants = append(tenants, t)
	}
	if rows.Err() != nil {
		s.log.Error("error iterating tenant rows", logger.ErrorField(rows.Err()))
		return nil, errors.New("error iterating tenant rows")
	}
	return tenants, nil
}

func (s *TenantStore) SearchTenants(ctx context.Context, filter TenantFilter) ([]interface{}, int, error) {
	q := `SELECT id, name, settings, created_at, updated_at FROM tenants`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, fmt.Sprintf("name ILIKE $%d", arg))
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "created_at DESC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "name" || col == "created_at" || col == "updated_at" {
			dir := "ASC"
			if strings.ToUpper(filter.SortDir) == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += fmt.Sprintf(" ORDER BY %s LIMIT $%d OFFSET $%d", order, arg, arg+1)
	args = append(args, filter.Limit, filter.Offset)
	countQ := "SELECT COUNT(*) FROM tenants"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-1]...)
	var total int
	if err := row.Scan(&total); err != nil {
		s.log.Error("failed to count tenants", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count tenants: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		s.log.Error("failed to query tenants", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query tenants: " + err.Error())
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Settings, &t.CreatedAt, &t.UpdatedAt); err != nil {
			s.log.Error("failed to scan tenant row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan tenant row")
		}
		tenants = append(tenants, t)
	}
	if rows.Err() != nil {
		s.log.Error("error iterating tenant rows", logger.ErrorField(rows.Err()))
		return nil, 0, errors.New("error iterating tenant rows")
	}
	return tenants, total, nil
}
