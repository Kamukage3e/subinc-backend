package fee

import (
	"context"
	"time"
)

// FeePlugin defines a hot-pluggable interface for fee logic.
type FeePlugin interface {
	Calculate(ctx context.Context, f Fee) (Fee, error)
	Describe(ctx context.Context, f Fee) (string, error)
	Name() string
	Version() string
	Capabilities() []string
	Initialize(config map[string]interface{}) error
}

// FeePluginRegistry holds registered plugins by name.
type FeePluginRegistry struct {
	plugins map[string]FeePlugin
}

func (r *FeePluginRegistry) Register(name string, plugin FeePlugin) {
	if r.plugins == nil {
		r.plugins = make(map[string]FeePlugin)
	}
	r.plugins[name] = plugin
}

func (r *FeePluginRegistry) Lookup(name string) (FeePlugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

// List returns all registered plugin names
func (r *FeePluginRegistry) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// Unregister removes a plugin from the registry
func (r *FeePluginRegistry) Unregister(name string) {
	if r.plugins == nil {
		return
	}
	delete(r.plugins, name)
}

// FeePluginConfig stores per-tenant plugin selection.
type FeePluginConfig struct {
	TenantID   string    `json:"tenant_id"`
	PluginName string    `json:"plugin_name"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Fee struct
// All fields required for SaaS billing and auditability
// Type: fixed, percent, etc.
type Fee struct {
	ID         string    `json:"id"`
	InvoiceID  string    `json:"invoice_id"`
	AccountID  string    `json:"account_id"`
	Amount     float64   `json:"amount"`
	Currency   string    `json:"currency"`
	Type       string    `json:"type"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Metadata   string    `json:"metadata"`
	PluginName string    `json:"plugin_name"`
}

func (f *Fee) Validate() *ValidationError {
	if f.InvoiceID == "" {
		return NewValidationError("invoice_id", "must not be empty")
	}
	if f.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if f.Amount < 0 {
		return NewValidationError("amount", "must be non-negative")
	}
	if f.Currency == "" {
		return NewValidationError("currency", "must not be empty")
	}
	if f.Type == "" {
		return NewValidationError("type", "must not be empty")
	}
	if f.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Error returns the error message
func (e *ValidationError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error with field, message, and code
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
		Code:    "validation_error",
	}
}

// Global hot-pluggable registry for fee plugins
var FeePlugins = &FeePluginRegistry{}

// RegisterFeePlugin registers a fee plugin by name at runtime.
func RegisterFeePlugin(name string, plugin FeePlugin) {
	FeePlugins.Register(name, plugin)
}

// LookupFeePlugin returns a fee plugin by name.
func LookupFeePlugin(name string) (FeePlugin, bool) {
	return FeePlugins.Lookup(name)
}
