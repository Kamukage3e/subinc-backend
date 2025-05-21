package fee

import (
	"context"
	"fmt"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
)

type FeeServiceAdapter struct {
	Store         *PostgresStore
	PluginManager *plugin.Manager
}

// NewFeeServiceAdapter creates a new fee service adapter
func NewFeeServiceAdapter(store *PostgresStore, pluginManager *plugin.Manager) *FeeServiceAdapter {
	return &FeeServiceAdapter{Store: store, PluginManager: pluginManager}
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

// GetFeePlugin retrieves the fee plugin configuration for a tenant
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
		logger.LogError("GetFeePlugin: plugin name required")
		return nil, fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("fee", pluginName)
	if !ok {
		logger.LogError("GetFeePlugin: plugin not found", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("fee plugin not found")
	}
	plugin, ok := p.(FeePlugin)
	if !ok {
		logger.LogError("GetFeePlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("invalid plugin type")
	}
	return plugin, nil
}

// RegisterFeePlugin registers a plugin with specified configuration
func (a *FeeServiceAdapter) RegisterFeePlugin(ctx context.Context, pluginName string, config map[string]interface{}) error {
	if pluginName == "" {
		logger.LogError("RegisterFeePlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("fee", pluginName)
	if !ok {
		logger.LogError("RegisterFeePlugin: plugin not found", logger.String("plugin_name", pluginName))
		return fmt.Errorf("fee plugin not found")
	}
	plugin, ok := p.(FeePlugin)
	if !ok {
		logger.LogError("RegisterFeePlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return fmt.Errorf("invalid plugin type")
	}
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("RegisterFeePlugin: failed to initialize plugin", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to initialize plugin")
	}
	return nil
}

// UnregisterFeePlugin removes a plugin from the registry
func (a *FeeServiceAdapter) UnregisterFeePlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		logger.LogError("UnregisterFeePlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	if err := a.PluginManager.UnregisterPlugin("fee", pluginName); err != nil {
		logger.LogError("UnregisterFeePlugin: failed", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to unregister plugin")
	}
	return nil
}
