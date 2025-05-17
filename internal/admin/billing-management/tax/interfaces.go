package tax

import (
	"context"
)

type TaxInfoService interface {
	SetTaxInfo(ctx context.Context, info TaxInfo) (TaxInfo, error)
	GetTaxInfo(ctx context.Context, tenantID string) (TaxInfo, error)
	ListTaxPlugins(ctx context.Context) ([]string, error)
	SetTaxPluginConfig(ctx context.Context, config TaxPluginConfig) (TaxPluginConfig, error)
	GetTaxPluginConfig(ctx context.Context, tenantID string) (TaxPluginConfig, error)
}

// TaxPlugin defines a hot-pluggable interface for tax calculation and compliance
type TaxPlugin interface {
	// Plugin identity
	Name() string    // Unique name of the tax plugin (e.g., "avalara", "taxjar")
	Version() string // Version in semver format

	// Core tax operations
	CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (float64, float64, error) // Calculate tax amount, tax rate, and any error
	ValidateAddress(ctx context.Context, address Address, tenantID string) (bool, error)                           // Validate address details
	GetTaxExemption(ctx context.Context, taxID string, country string, tenantID string) (bool, string, error)      // Check if tax ID provides exemption

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize with configuration parameters
	Capabilities() []string                         // Return supported jurisdictions, reporting features
}

// TaxPluginRegistry manages a collection of tax plugins
type TaxPluginRegistry struct {
	plugins map[string]TaxPlugin
}

// Register adds a tax plugin to the registry
func (r *TaxPluginRegistry) Register(plugin TaxPlugin) {
	if plugin == nil {
		return
	}
	name := plugin.Name()
	if name == "" {
		return
	}
	r.plugins[name] = plugin
}

// Lookup retrieves a tax plugin by name
func (r *TaxPluginRegistry) Lookup(name string) (TaxPlugin, bool) {
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// List returns all registered tax plugin names
func (r *TaxPluginRegistry) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// Unregister removes a tax plugin from the registry
func (r *TaxPluginRegistry) Unregister(name string) {
	delete(r.plugins, name)
}
