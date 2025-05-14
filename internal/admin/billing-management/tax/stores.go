package tax


import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Implement TaxInfoService
func (s *PostgresStore) SetTaxInfo(ctx context.Context, info TaxInfo) (TaxInfo, error) {
	const q = `INSERT INTO tax_info (id, tenant_id, country, region, tax_id, tax_rate, currency, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (tenant_id) DO UPDATE SET country = $3, region = $4, tax_id = $5, tax_rate = $6, currency = $7, updated_at = $9 RETURNING id, tenant_id, country, region, tax_id, tax_rate, currency, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, info.ID, info.TenantID, info.Country, info.Region, info.TaxID, info.TaxRate, info.Currency, info.CreatedAt, info.UpdatedAt)
	var out TaxInfo
	if err := row.Scan(&out.ID, &out.TenantID, &out.Country, &out.Region, &out.TaxID, &out.TaxRate, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("SetTaxInfo failed", logger.ErrorField(err), logger.Any("info", info))
		return TaxInfo{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetTaxInfo(ctx context.Context, tenantID string) (TaxInfo, error) {
	const q = `SELECT id, tenant_id, country, region, tax_id, tax_rate, currency, created_at, updated_at FROM tax_info WHERE tenant_id = $1`
	row := s.DB.QueryRow(ctx, q, tenantID)
	var out TaxInfo
	if err := row.Scan(&out.ID, &out.TenantID, &out.Country, &out.Region, &out.TaxID, &out.TaxRate, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("GetTaxInfo failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return TaxInfo{}, err
	}
	return out, nil
}



// --- TaxPluginConfig CRUD ---
func (s *PostgresStore) SetTaxPluginConfig(ctx context.Context, tenantID, pluginName string) (TaxPluginConfig, error) {
	if tenantID == "" {
		return TaxPluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	if pluginName == "" {
		return TaxPluginConfig{}, NewValidationError("plugin_name", "must not be empty")
	}
	updatedAt := time.Now().UTC()
	const q = `INSERT INTO tax_plugin_config (tenant_id, plugin_name, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET plugin_name = $2, updated_at = $3
		RETURNING tenant_id, plugin_name, updated_at`
	row := s.DB.QueryRow(ctx, q, tenantID, pluginName, updatedAt)
	var out TaxPluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("SetTaxPluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", pluginName))
		return TaxPluginConfig{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetTaxPluginConfig(ctx context.Context, tenantID string) (TaxPluginConfig, error) {
	if tenantID == "" {
		return TaxPluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	const q = `SELECT tenant_id, plugin_name, updated_at FROM tax_plugin_config WHERE tenant_id = $1`
	row := s.DB.QueryRow(ctx, q, tenantID)
	var out TaxPluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("GetTaxPluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return TaxPluginConfig{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListTaxPlugins(ctx context.Context) ([]string, error) {
	// Returns all registered plugin names from the in-memory registry
	plugins := []string{}
	for name := range TaxPlugins.plugins {
		plugins = append(plugins, name)
	}
	return plugins, nil
}


