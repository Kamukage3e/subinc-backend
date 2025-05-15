package tax

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
)

type TaxHandler struct {
	TaxInfoService TaxInfoService
	Store          PostgresStore
}

type PostgresStore struct {
	DB                  *pgxpool.Pool
	AuditLogger         security_management.AuditLogger
	ServerConfigService *server_config.Service
}

// TaxInfo for multi-currency, multi-region, VAT/GST compliance
type TaxInfo struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Country   string    `json:"country"`
	Region    string    `json:"region"`
	TaxID     string    `json:"tax_id"`
	TaxRate   float64   `json:"tax_rate"`
	Currency  string    `json:"currency"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TaxPlugin defines a pluggable interface for tax/VAT calculation per region/country.
type TaxPlugin interface {
	CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (taxAmount, taxRate float64, err error)
}

// TaxPluginRegistry holds registered plugins by name and region/country.
type TaxPluginRegistry struct {
	plugins map[string]TaxPlugin // key: plugin name
}

// Register adds a plugin to the registry.
func (r *TaxPluginRegistry) Register(name string, plugin TaxPlugin) {
	if r.plugins == nil {
		r.plugins = make(map[string]TaxPlugin)
	}
	r.plugins[name] = plugin
}

// Lookup returns a plugin by name.
func (r *TaxPluginRegistry) Lookup(name string) (TaxPlugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

// TaxPluginConfig stores per-tenant plugin selection.
type TaxPluginConfig struct {
	TenantID   string    `json:"tenant_id"`
	PluginName string    `json:"plugin_name"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// DefaultTaxPlugin applies no tax (0%).
type DefaultTaxPlugin struct{}

func (DefaultTaxPlugin) CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (float64, float64, error) {
	return 0, 0, nil
}

// EUTaxPlugin applies a flat 20% VAT for demonstration.
type EUTaxPlugin struct{}

func (EUTaxPlugin) CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (float64, float64, error) {
	amount := invoice.Amount
	taxRate := 20.0
	return amount * taxRate / 100, taxRate, nil
}

// TaxPlugins is the global registry for all tax plugins.
var TaxPlugins = func() *TaxPluginRegistry {
	r := &TaxPluginRegistry{}
	r.Register("default", DefaultTaxPlugin{})
	r.Register("eu_vat", EUTaxPlugin{})
	return r
}()

func NewValidationError(field, msg string) *Error {
	return &Error{
		Code:    "VALIDATION_ERROR",
		Message: msg,
		Field:   field,
	}
}

type Error struct {
	Code    string
	Message string
	Field   string
	Err     error
}

func (e *Error) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

type Account struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	Currency  string    `json:"currency"` // ISO 4217, e.g. USD
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Invoice struct {
	ID               string    `json:"id"`
	AccountID        string    `json:"account_id"`
	Amount           float64   `json:"amount"`
	Currency         string    `json:"currency"` // ISO 4217, e.g. USD
	OriginalAmount   float64   `json:"original_amount,omitempty"`
	OriginalCurrency string    `json:"original_currency,omitempty"`
	Status           string    `json:"status"`
	DueDate          time.Time `json:"due_date"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	TaxAmount        float64   `json:"tax_amount"`
	TaxRate          float64   `json:"tax_rate"`
	Fees             string    `json:"fees"`
}
