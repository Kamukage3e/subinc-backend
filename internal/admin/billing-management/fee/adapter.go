package fee

import (
	"context"
)

type FeeServiceAdapter struct {
	Store *PostgresStore
}

// NewFeeServiceAdapter creates a new fee service adapter
func NewFeeServiceAdapter(store *PostgresStore) *FeeServiceAdapter {
	return &FeeServiceAdapter{Store: store}
}

// CreateFee creates a new fee in the system
func (a *FeeServiceAdapter) CreateFee(ctx context.Context, f Fee) (Fee, error) {
	return a.Store.CreateFee(ctx, f)
}

// GetFee retrieves a fee by ID
func (a *FeeServiceAdapter) GetFee(ctx context.Context, id string) (Fee, error) {
	return a.Store.GetFee(ctx, id)
}

// UpdateFee updates an existing fee
func (a *FeeServiceAdapter) UpdateFee(ctx context.Context, f Fee) (Fee, error) {
	return a.Store.UpdateFee(ctx, f)
}

// ListFees lists all fees
func (a *FeeServiceAdapter) ListFees(ctx context.Context, tenantID string, page int, limit int) ([]Fee, error) {
	return a.Store.ListFees(ctx, page, limit)
}

// DeleteFee removes a fee from the system
func (a *FeeServiceAdapter) DeleteFee(ctx context.Context, id string) error {
	return a.Store.DeleteFee(ctx, id)
}

// SetFeePluginConfig sets the fee plugin configuration for a tenant
func (a *FeeServiceAdapter) SetFeePluginConfig(ctx context.Context, tenantID, pluginName string) (FeePluginConfig, error) {
	return a.Store.SetFeePluginConfig(ctx, tenantID, pluginName)
}

// GetFeePluginConfig retrieves the fee plugin configuration for a tenant
func (a *FeeServiceAdapter) GetFeePluginConfig(ctx context.Context, tenantID string) (FeePluginConfig, error) {
	return a.Store.GetFeePluginConfig(ctx, tenantID)
}

// DisableFeePlugin removes a fee plugin configuration for a tenant
func (a *FeeServiceAdapter) DisableFeePlugin(ctx context.Context, tenantID, pluginName string) error {
	return a.Store.DisableFeePlugin(ctx, tenantID, pluginName)
}
