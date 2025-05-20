package tax

import (
	"context"
	"fmt"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// TaxStore handles tax rule storage
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
func (s *PostgresStore) SetTaxPluginConfig(ctx context.Context, config TaxPluginConfig) (TaxPluginConfig, error) {
	const query = `
		INSERT INTO tax_plugin_configs (tenant_id, plugin_name, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) 
		DO UPDATE SET
			plugin_name = $2,
			updated_at = $3
		RETURNING tenant_id, plugin_name, updated_at
	`

	var result TaxPluginConfig
	err := s.DB.QueryRow(ctx, query,
		config.TenantID,
		config.PluginName,
		config.UpdatedAt,
	).Scan(
		&result.TenantID,
		&result.PluginName,
		&result.UpdatedAt,
	)

	if err != nil {
		return TaxPluginConfig{}, fmt.Errorf("failed to save tax plugin config: %w", err)
	}

	return result, nil
}

func (s *PostgresStore) GetTaxPluginConfig(ctx context.Context, tenantID string) (TaxPluginConfig, error) {
	const query = `
		SELECT tenant_id, plugin_name, updated_at
		FROM tax_plugin_configs
		WHERE tenant_id = $1
	`

	var result TaxPluginConfig
	err := s.DB.QueryRow(ctx, query, tenantID).Scan(
		&result.TenantID,
		&result.PluginName,
		&result.UpdatedAt,
	)

	if err != nil {
		return TaxPluginConfig{}, fmt.Errorf("failed to get tax plugin config: %w", err)
	}

	return result, nil
}

func (s *PostgresStore) ListTaxPlugins(ctx context.Context) ([]string, error) {
	// Return the list of registered plugins
	return TaxPlugins.List(), nil
}

// RemoveTaxPluginConfig removes a tax plugin configuration for a specific tenant
func (s *PostgresStore) RemoveTaxPluginConfig(ctx context.Context, tenantID, pluginName string) error {
	const query = `
		DELETE FROM tax_plugin_configs
		WHERE tenant_id = $1 AND plugin_name = $2
	`

	result, err := s.DB.Exec(ctx, query, tenantID, pluginName)
	if err != nil {
		return fmt.Errorf("failed to remove tax plugin config: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("tax plugin config not found for tenant %s and plugin %s", tenantID, pluginName)
	}

	return nil
}
