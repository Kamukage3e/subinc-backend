package fee

import (
	"context"
	"fmt"
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
func (a *FeeServiceAdapter) ListFees(ctx context.Context, page, pageSize int) ([]Fee, error) {
	return a.Store.ListFees(ctx, page, pageSize)
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

// ListFeePlugins returns all registered fee plugins
func (a *FeeServiceAdapter) ListFeePlugins(ctx context.Context) ([]string, error) {
	pluginNames := FeePlugins.List()
	return pluginNames, nil
}

// GetFeePlugin returns a specific fee plugin by name
func (a *FeeServiceAdapter) GetFeePlugin(ctx context.Context, pluginName string) (FeePlugin, error) {
	if pluginName == "" {
		return nil, fmt.Errorf("plugin name is required")
	}

	plugin, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		return nil, fmt.Errorf("fee plugin '%s' not found", pluginName)
	}

	return plugin, nil
}

// RegisterFeePlugin registers a plugin with specified configuration
func (a *FeeServiceAdapter) RegisterFeePlugin(ctx context.Context, pluginName string, config map[string]interface{}) error {
	if pluginName == "" {
		return fmt.Errorf("plugin name is required")
	}

	plugin, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		return fmt.Errorf("fee plugin '%s' not found", pluginName)
	}

	// Initialize the plugin with configuration
	if err := plugin.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize plugin: %v", err)
	}

	return nil
}

// UnregisterFeePlugin removes a plugin from the registry
func (a *FeeServiceAdapter) UnregisterFeePlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		return fmt.Errorf("plugin name is required")
	}

	_, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		return fmt.Errorf("fee plugin '%s' not found", pluginName)
	}

	FeePlugins.Unregister(pluginName)
	return nil
}
