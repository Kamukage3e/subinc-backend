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
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// GetTenantSettings fetches settings JSON for a tenant by id
func (s *PostgresStore) GetTenantSettings(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	if tenantID == "" {
		logger.LogError("tenant id required")
		return nil, errors.New("tenant id required")
	}
	key := "tenant_settings_" + tenantID
	cfg, err := s.ServerConfigService.Get(ctx, key)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return map[string]interface{}{}, nil
		}
		logger.LogError("failed to get tenant settings", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.Value), &settings); err != nil {
		logger.LogError("invalid settings JSON", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, errors.New("invalid settings JSON")
	}
	return settings, nil
}

// UpdateTenantSettings updates the settings JSON for a tenant by id
func (s *PostgresStore) UpdateTenantSettings(ctx context.Context, tenantID string, input map[string]interface{}) (map[string]interface{}, error) {
	if tenantID == "" {
		logger.LogError("tenant id required")
		return nil, errors.New("tenant id required")
	}
	settingsBytes, err := json.Marshal(input)
	if err != nil {
		logger.LogError("invalid settings input", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, errors.New("invalid settings input")
	}
	key := "tenant_settings_" + tenantID
	_, err = s.ServerConfigService.Set(ctx, key, string(settingsBytes), "system")
	if err != nil {
		logger.LogError("failed to update tenant settings", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	return input, nil
}

func (s *PostgresStore) CreateTenant(ctx context.Context, tenant *Tenant) error {
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
		logger.LogError("failed to create tenant", logger.ErrorField(err), logger.String("id", tenant.ID), logger.String("name", tenant.Name))
		return errors.New("failed to create tenant: " + err.Error())
	}
	return nil
}

func (s *PostgresStore) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	tenant.UpdatedAt = time.Now().UTC()
	const q = `UPDATE tenants SET name = $2, settings = $3, updated_at = $4 WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, tenant.ID, tenant.Name, tenant.Settings, tenant.UpdatedAt)
	if err != nil {
		logger.LogError("failed to update tenant", logger.ErrorField(err), logger.String("id", tenant.ID), logger.String("name", tenant.Name))
		return errors.New("failed to update tenant: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("tenant not found", logger.String("id", tenant.ID))
		return errors.New("tenant not found")
	}
	return nil
}

func (s *PostgresStore) DeleteTenant(ctx context.Context, id string) error {
	const q = `DELETE FROM tenants WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete tenant", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete tenant: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("tenant not found", logger.String("id", id))
		return errors.New("tenant not found")
	}
	return nil
}

func (s *PostgresStore) ListTenants(ctx context.Context) ([]interface{}, error) {
	const q = `SELECT id, name, settings, created_at, updated_at FROM tenants`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("failed to query tenants", logger.ErrorField(err))
		return nil, errors.New("failed to query tenants")
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Settings, &t.CreatedAt, &t.UpdatedAt); err != nil {
			logger.LogError("failed to scan tenant row", logger.ErrorField(err))
			return nil, errors.New("failed to scan tenant row")
		}
		tenants = append(tenants, t)
	}
	if rows.Err() != nil {
		logger.LogError("error iterating tenant rows", logger.ErrorField(rows.Err()))
		return nil, errors.New("error iterating tenant rows")
	}
	return tenants, nil
}

func (s *PostgresStore) SearchTenants(ctx context.Context, filter TenantFilter) ([]interface{}, int, error) {
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
		logger.LogError("failed to count tenants", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count tenants: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query tenants", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query tenants: " + err.Error())
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Settings, &t.CreatedAt, &t.UpdatedAt); err != nil {
			logger.LogError("failed to scan tenant row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan tenant row")
		}
		tenants = append(tenants, t)
	}
	if rows.Err() != nil {
		logger.LogError("error iterating tenant rows", logger.ErrorField(rows.Err()))
		return nil, 0, errors.New("error iterating tenant rows")
	}
	return tenants, total, nil
}

// --- TenantLifecycleService Postgres Implementation ---

func (s *PostgresStore) SetTenantStatus(ctx context.Context, tenantID string, status TenantStatus) error {
	if tenantID == "" {
		return errors.New("tenant_id required")
	}
	if status != TenantStatusPending && status != TenantStatusActive && status != TenantStatusSuspended && status != TenantStatusDeleted {
		return errors.New("invalid status")
	}
	const q = `UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2`
	_, err := s.DB.Exec(ctx, q, status, tenantID)
	if err != nil {
		logger.LogError("failed to update tenant status", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("status", string(status)))
		return errors.New("failed to update tenant status")
	}
	return nil
}

func (s *PostgresStore) GetTenantStatus(ctx context.Context, tenantID string) (TenantStatus, error) {
	if tenantID == "" {
		return "", errors.New("tenant_id required")
	}
	const q = `SELECT status FROM tenants WHERE id = $1`
	var status TenantStatus
	err := s.DB.QueryRow(ctx, q, tenantID).Scan(&status)
	if err != nil {
		logger.LogError("failed to get tenant status", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return "", errors.New("failed to get tenant status")
	}
	return status, nil
}

// GetTenant retrieves a single tenant by ID
func (s *PostgresStore) GetTenant(ctx context.Context, id string) (Tenant, error) {
	if id == "" {
		return Tenant{}, errors.New("tenant id required")
	}

	const q = `SELECT id, name, status, settings, created_at, updated_at FROM tenants WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)

	var tenant Tenant
	err := row.Scan(&tenant.ID, &tenant.Name, &tenant.Status, &tenant.Settings, &tenant.CreatedAt, &tenant.UpdatedAt)
	if err != nil {
		logger.LogError("failed to get tenant", logger.ErrorField(err), logger.String("id", id))
		if strings.Contains(err.Error(), "no rows") {
			return Tenant{}, errors.New("tenant not found")
		}
		return Tenant{}, errors.New("failed to get tenant: " + err.Error())
	}

	return tenant, nil
}

func NewPostgresStore(db *pgxpool.Pool, serverConfigService *server_config.Service, auditLogger security_management.AuditLogger) *PostgresStore {
	if db == nil {
		panic("PostgresStore: DB must not be nil")
	}
	if serverConfigService == nil {
		panic("PostgresStore: ServerConfigService must not be nil (required for all secrets/keys)")
	}
	return &PostgresStore{
		DB:                  db,
		ServerConfigService: serverConfigService,
		AuditLogger:         auditLogger,
	}
}
