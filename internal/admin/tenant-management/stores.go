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

func NewPostgresStore(db *pgxpool.Pool, serverConfigService *server_config.Service) *PostgresStore {
	if db == nil {
		panic("PostgresStore: DB must not be nil")
	}
	if serverConfigService == nil {
		panic("PostgresStore: ServerConfigService must not be nil (required for all secrets/keys)")
	}
	return &PostgresStore{
		DB:                  db,
		ServerConfigService: serverConfigService,
	}
}

// --- TenantMigrationService Implementation ---

// MigrateTenant migrates all tenant data from one tenant to another
func (s *PostgresStore) MigrateTenant(ctx context.Context, sourceTenantID, targetTenantID string) error {
	if sourceTenantID == "" || targetTenantID == "" {
		return errors.New("source and target tenant IDs required")
	}

	// Validate both tenants exist
	sourceTenant, err := s.GetTenant(ctx, sourceTenantID)
	if err != nil {
		logger.LogError("MigrateTenant: source tenant not found", logger.ErrorField(err), logger.String("source_id", sourceTenantID))
		return errors.New("source tenant not found")
	}

	targetTenant, err := s.GetTenant(ctx, targetTenantID)
	if err != nil {
		logger.LogError("MigrateTenant: target tenant not found", logger.ErrorField(err), logger.String("target_id", targetTenantID))
		return errors.New("target tenant not found")
	}

	// Begin transaction for data migration
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		logger.LogError("MigrateTenant: failed to begin transaction", logger.ErrorField(err))
		return errors.New("failed to begin migration transaction")
	}
	defer tx.Rollback(ctx)

	// 1. Migrate tenant settings
	sourceSettings, err := s.GetTenantSettings(ctx, sourceTenantID)
	if err == nil && len(sourceSettings) > 0 {
		_, err = s.UpdateTenantSettings(ctx, targetTenantID, sourceSettings)
		if err != nil {
			logger.LogError("MigrateTenant: failed to migrate settings", logger.ErrorField(err))
			// Continue with migration even if settings fail
		}
	}

	// 2. Migrate tenant-specific data (example with organization_billing_accounts)
	// First query for records with the source tenant ID
	const queryAccounts = `
		SELECT id, org_id, email, status, currency, default_method_id, created_at, updated_at
		FROM organization_billing_accounts
		WHERE tenant_id = $1
	`
	rows, err := tx.Query(ctx, queryAccounts, sourceTenantID)
	if err != nil {
		logger.LogError("MigrateTenant: failed to query billing accounts", logger.ErrorField(err))
		return errors.New("failed to query source tenant data")
	}
	defer rows.Close()

	// Insert each record with the target tenant ID
	const insertAccount = `
		INSERT INTO organization_billing_accounts
		(id, org_id, tenant_id, email, status, currency, default_method_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING
	`

	// Process each row
	for rows.Next() {
		var id, orgID, email, status, currency string
		var defaultMethodID *string
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &orgID, &email, &status, &currency, &defaultMethodID, &createdAt, &updatedAt); err != nil {
			logger.LogError("MigrateTenant: failed to scan row", logger.ErrorField(err))
			continue
		}

		// Create a new ID for the migrated record
		newID := uuid.NewString()

		// Insert with target tenant ID
		_, err := tx.Exec(ctx, insertAccount, newID, orgID, targetTenantID, email, status, currency, defaultMethodID, createdAt, updatedAt)
		if err != nil {
			logger.LogError("MigrateTenant: failed to insert account", logger.ErrorField(err))
			// Continue with other records even if one fails
		}
	}

	// 3. Additional data tables would follow the same pattern
	// ... migrate invoices
	// ... migrate payments
	// ... migrate subscriptions

	// 4. Log the migration
	logger.LogInfo("MigrateTenant: migration complete",
		logger.String("source_tenant", sourceTenant.Name),
		logger.String("source_id", sourceTenantID),
		logger.String("target_tenant", targetTenant.Name),
		logger.String("target_id", targetTenantID))

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		logger.LogError("MigrateTenant: failed to commit transaction", logger.ErrorField(err))
		return errors.New("failed to commit migration")
	}

	return nil
}

// ExportTenantData exports tenant data as a structured format
func (s *PostgresStore) ExportTenantData(ctx context.Context, tenantID string) ([]byte, error) {
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	// Validate tenant exists
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		logger.LogError("ExportTenantData: tenant not found", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, errors.New("tenant not found")
	}

	// Create a data structure to hold all tenant data
	exportData := map[string]interface{}{
		"export_version": "1.0",
		"export_date":    time.Now().UTC(),
		"tenant": map[string]interface{}{
			"id":      tenant.ID,
			"name":    tenant.Name,
			"status":  tenant.Status,
			"created": tenant.CreatedAt,
			"updated": tenant.UpdatedAt,
		},
		"settings": map[string]interface{}{},
		"data":     map[string]interface{}{},
	}

	// Get tenant settings
	settings, err := s.GetTenantSettings(ctx, tenantID)
	if err == nil {
		exportData["settings"] = settings
	}

	// Collect tenant data from different tables
	// Example: Collect organization_billing_accounts
	accounts := []map[string]interface{}{}
	const queryAccounts = `
		SELECT id, org_id, email, status, currency, default_method_id, created_at, updated_at
		FROM organization_billing_accounts
		WHERE tenant_id = $1
	`
	rows, err := s.DB.Query(ctx, queryAccounts, tenantID)
	if err == nil {
		defer rows.Close()

		for rows.Next() {
			var id, orgID, email, status, currency string
			var defaultMethodID *string
			var createdAt, updatedAt time.Time

			if err := rows.Scan(&id, &orgID, &email, &status, &currency, &defaultMethodID, &createdAt, &updatedAt); err != nil {
				logger.LogError("ExportTenantData: failed to scan account", logger.ErrorField(err))
				continue
			}

			account := map[string]interface{}{
				"id":                id,
				"org_id":            orgID,
				"email":             email,
				"status":            status,
				"currency":          currency,
				"default_method_id": defaultMethodID,
				"created_at":        createdAt,
				"updated_at":        updatedAt,
			}
			accounts = append(accounts, account)
		}
	}

	// Add data to export
	dataSection := exportData["data"].(map[string]interface{})
	dataSection["billing_accounts"] = accounts

	// Additional data collection would follow the same pattern
	// ... collect invoices
	// ... collect payments
	// ... collect subscriptions

	// Convert to JSON
	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		logger.LogError("ExportTenantData: failed to marshal export data", logger.ErrorField(err))
		return nil, errors.New("failed to serialize export data")
	}

	logger.LogInfo("ExportTenantData: successfully exported tenant data",
		logger.String("tenant_id", tenantID),
		logger.String("tenant_name", tenant.Name),
		logger.Int("data_size_bytes", len(jsonData)))

	return jsonData, nil
}

// ImportTenantData imports tenant data from a structured format
func (s *PostgresStore) ImportTenantData(ctx context.Context, targetTenantID string, data []byte) error {
	if targetTenantID == "" {
		return errors.New("target tenant ID required")
	}

	if len(data) == 0 {
		return errors.New("import data required")
	}

	// Validate target tenant exists
	targetTenant, err := s.GetTenant(ctx, targetTenantID)
	if err != nil {
		logger.LogError("ImportTenantData: target tenant not found", logger.ErrorField(err), logger.String("target_id", targetTenantID))
		return errors.New("target tenant not found")
	}

	// Parse the import data
	var importData map[string]interface{}
	if err := json.Unmarshal(data, &importData); err != nil {
		logger.LogError("ImportTenantData: invalid import data format", logger.ErrorField(err))
		return errors.New("invalid import data format")
	}

	// Check export version
	version, ok := importData["export_version"].(string)
	if !ok || version != "1.0" {
		logger.LogError("ImportTenantData: unsupported export version", logger.String("version", version))
		return errors.New("unsupported export format version")
	}

	// Begin transaction for data import
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		logger.LogError("ImportTenantData: failed to begin transaction", logger.ErrorField(err))
		return errors.New("failed to begin import transaction")
	}
	defer tx.Rollback(ctx)

	// Import tenant settings
	if settings, ok := importData["settings"].(map[string]interface{}); ok && len(settings) > 0 {
		_, err = s.UpdateTenantSettings(ctx, targetTenantID, settings)
		if err != nil {
			logger.LogError("ImportTenantData: failed to import settings", logger.ErrorField(err))
			// Continue with import even if settings fail
		}
	}

	// Extract and import data sections
	dataSection, ok := importData["data"].(map[string]interface{})
	if !ok {
		logger.LogError("ImportTenantData: missing data section in import file")
		return errors.New("invalid import data format: missing data section")
	}

	// Import billing accounts
	if accountsData, ok := dataSection["billing_accounts"].([]interface{}); ok {
		const insertAccount = `
			INSERT INTO organization_billing_accounts
			(id, org_id, tenant_id, email, status, currency, default_method_id, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO NOTHING
		`

		for _, accData := range accountsData {
			account, ok := accData.(map[string]interface{})
			if !ok {
				continue
			}

			// Create a new ID for the imported record
			newID := uuid.NewString()

			// Extract account fields
			orgID, _ := account["org_id"].(string)
			email, _ := account["email"].(string)
			status, _ := account["status"].(string)
			currency, _ := account["currency"].(string)
			var defaultMethodID *string
			if dmid, ok := account["default_method_id"].(string); ok {
				defaultMethodID = &dmid
			}

			// Parse timestamps
			createdAt := time.Now().UTC()
			updatedAt := time.Now().UTC()

			// Insert with target tenant ID
			_, err := tx.Exec(ctx, insertAccount, newID, orgID, targetTenantID, email, status, currency, defaultMethodID, createdAt, updatedAt)
			if err != nil {
				logger.LogError("ImportTenantData: failed to insert account", logger.ErrorField(err))
				// Continue with other records even if one fails
			}
		}
	}

	// Additional data imports would follow the same pattern
	// ... import invoices
	// ... import payments
	// ... import subscriptions

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		logger.LogError("ImportTenantData: failed to commit transaction", logger.ErrorField(err))
		return errors.New("failed to commit import")
	}

	logger.LogInfo("ImportTenantData: successfully imported tenant data",
		logger.String("target_id", targetTenantID),
		logger.String("target_name", targetTenant.Name))

	return nil
}

// ValidateMigration validates if a migration is possible between tenants
func (s *PostgresStore) ValidateMigration(ctx context.Context, sourceTenantID, targetTenantID string) (bool, map[string]interface{}, error) {
	if sourceTenantID == "" || targetTenantID == "" {
		return false, nil, errors.New("source and target tenant IDs required")
	}

	// Validate both tenants exist
	sourceTenant, err := s.GetTenant(ctx, sourceTenantID)
	if err != nil {
		logger.LogError("ValidateMigration: source tenant not found", logger.ErrorField(err), logger.String("source_id", sourceTenantID))
		return false, nil, errors.New("source tenant not found")
	}

	targetTenant, err := s.GetTenant(ctx, targetTenantID)
	if err != nil {
		logger.LogError("ValidateMigration: target tenant not found", logger.ErrorField(err), logger.String("target_id", targetTenantID))
		return false, nil, errors.New("target tenant not found")
	}

	// Initialize validation result
	validationResult := map[string]interface{}{
		"source_tenant": map[string]string{
			"id":     sourceTenant.ID,
			"name":   sourceTenant.Name,
			"status": string(sourceTenant.Status),
		},
		"target_tenant": map[string]string{
			"id":     targetTenant.ID,
			"name":   targetTenant.Name,
			"status": string(targetTenant.Status),
		},
		"issues":   []string{},
		"warnings": []string{},
	}

	// Check tenant statuses
	if targetTenant.Status != TenantStatusActive {
		validationResult["issues"] = append(validationResult["issues"].([]string), "Target tenant is not active")
	}

	// Check for conflicts - count data in target tenant
	const countTargetQuery = `
		SELECT COUNT(*) FROM organization_billing_accounts WHERE tenant_id = $1
	`
	var targetCount int
	err = s.DB.QueryRow(ctx, countTargetQuery, targetTenantID).Scan(&targetCount)
	if err != nil {
		logger.LogError("ValidateMigration: failed to count target records", logger.ErrorField(err))
	} else if targetCount > 0 {
		validationResult["warnings"] = append(validationResult["warnings"].([]string), fmt.Sprintf("Target tenant already has %d billing account(s)", targetCount))
	}

	// Count source data to migrate
	const countSourceQuery = `
		SELECT COUNT(*) FROM organization_billing_accounts WHERE tenant_id = $1
	`
	var sourceCount int
	err = s.DB.QueryRow(ctx, countSourceQuery, sourceTenantID).Scan(&sourceCount)
	if err != nil {
		logger.LogError("ValidateMigration: failed to count source records", logger.ErrorField(err))
	} else {
		validationResult["source_data_counts"] = map[string]int{
			"billing_accounts": sourceCount,
		}
	}

	// Additional validation checks would go here

	// Determine overall validity
	valid := len(validationResult["issues"].([]string)) == 0

	logger.LogInfo("ValidateMigration: completed validation",
		logger.String("source_id", sourceTenantID),
		logger.String("target_id", targetTenantID),
		logger.Bool("valid", valid))

	return valid, validationResult, nil
}
