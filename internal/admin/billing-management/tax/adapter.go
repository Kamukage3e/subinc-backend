package tax

import (
	"context"
	"fmt"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
)

// TaxServiceAdapter adapts the PostgresStore to the TaxInfoService interface
type TaxServiceAdapter struct {
	Store         *PostgresStore
	PluginManager *plugin.Manager
}

// NewTaxServiceAdapter creates a new tax service adapter
func NewTaxServiceAdapter(store *PostgresStore, pluginManager *plugin.Manager) *TaxServiceAdapter {
	return &TaxServiceAdapter{Store: store, PluginManager: pluginManager}
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
	return a.PluginManager.ListPlugins("tax"), nil
}

// GetTaxPlugin retrieves a tax plugin by name
func (a *TaxServiceAdapter) GetTaxPlugin(ctx context.Context, pluginName string) (TaxPlugin, error) {
	if pluginName == "" {
		logger.LogError("GetTaxPlugin: plugin name required")
		return nil, fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("tax", pluginName)
	if !ok {
		logger.LogError("GetTaxPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("tax plugin not found")
	}
	plugin, ok := p.(TaxPlugin)
	if !ok {
		logger.LogError("GetTaxPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("invalid plugin type")
	}
	return plugin, nil
}

// RegisterTaxPlugin registers a tax plugin
func (a *TaxServiceAdapter) RegisterTaxPlugin(ctx context.Context, pluginName string, config map[string]interface{}) error {
	if pluginName == "" {
		logger.LogError("RegisterTaxPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("tax", pluginName)
	if !ok {
		logger.LogError("RegisterTaxPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return fmt.Errorf("tax plugin not found")
	}
	plugin, ok := p.(TaxPlugin)
	if !ok {
		logger.LogError("RegisterTaxPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return fmt.Errorf("invalid plugin type")
	}
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("RegisterTaxPlugin: failed to initialize plugin", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to initialize plugin")
	}
	return nil
}

// UnregisterTaxPlugin unregisters a tax plugin
func (a *TaxServiceAdapter) UnregisterTaxPlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		logger.LogError("UnregisterTaxPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	if err := a.PluginManager.UnregisterPlugin("tax", pluginName); err != nil {
		logger.LogError("UnregisterTaxPlugin: failed", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to unregister plugin")
	}
	return nil
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

// ConfigureTaxPlugin configures a tax plugin for a tenant
func (a *TaxServiceAdapter) ConfigureTaxPlugin(ctx context.Context, pluginName string, tenantID string, config map[string]interface{}) error {
	if pluginName == "" {
		logger.LogError("ConfigureTaxPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("tax", pluginName)
	if !ok {
		logger.LogError("ConfigureTaxPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return fmt.Errorf("tax plugin not found")
	}
	plugin, ok := p.(TaxPlugin)
	if !ok {
		logger.LogError("ConfigureTaxPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return fmt.Errorf("invalid plugin type")
	}
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("ConfigureTaxPlugin: failed to initialize plugin", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to initialize plugin")
	}
	return nil
}
