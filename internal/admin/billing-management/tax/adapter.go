package tax

import (
	"context"
)

// TaxServiceAdapter adapts the PostgresStore to the TaxInfoService interface
type TaxServiceAdapter struct {
	Store *PostgresStore
}

// NewTaxServiceAdapter creates a new tax service adapter
func NewTaxServiceAdapter(store *PostgresStore) *TaxServiceAdapter {
	return &TaxServiceAdapter{Store: store}
}

// SetTaxInfo sets tax information for a tenant
func (a *TaxServiceAdapter) SetTaxInfo(ctx context.Context, info TaxInfo) (TaxInfo, error) {
	return a.Store.SetTaxInfo(ctx, info)
}

// GetTaxInfo retrieves tax information for a tenant
func (a *TaxServiceAdapter) GetTaxInfo(ctx context.Context, tenantID string) (TaxInfo, error) {
	return a.Store.GetTaxInfo(ctx, tenantID)
}

// ListTaxPlugins returns a list of available tax plugins
func (a *TaxServiceAdapter) ListTaxPlugins(ctx context.Context) ([]string, error) {
	return a.Store.ListTaxPlugins(ctx)
}

// SetTaxPluginConfig sets the tax plugin configuration for a tenant
func (a *TaxServiceAdapter) SetTaxPluginConfig(ctx context.Context, config TaxPluginConfig) (TaxPluginConfig, error) {
	return a.Store.SetTaxPluginConfig(ctx, config)
}

// GetTaxPluginConfig retrieves the tax plugin configuration for a tenant
func (a *TaxServiceAdapter) GetTaxPluginConfig(ctx context.Context, tenantID string) (TaxPluginConfig, error) {
	return a.Store.GetTaxPluginConfig(ctx, tenantID)
}

// RemoveTaxPluginConfig removes the tax plugin configuration for a tenant
func (a *TaxServiceAdapter) RemoveTaxPluginConfig(ctx context.Context, tenantID, pluginName string) error {
	return a.Store.RemoveTaxPluginConfig(ctx, tenantID, pluginName)
}
