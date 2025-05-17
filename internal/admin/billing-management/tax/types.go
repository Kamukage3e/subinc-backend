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

// TaxPluginConfig stores per-tenant plugin selection.
type TaxPluginConfig struct {
	TenantID   string    `json:"tenant_id"`
	PluginName string    `json:"plugin_name"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// DefaultTaxPlugin applies no tax (0%)
type DefaultTaxPlugin struct{}

func (p DefaultTaxPlugin) Name() string {
	return "default"
}

func (p DefaultTaxPlugin) Version() string {
	return "1.0.0"
}

func (p DefaultTaxPlugin) CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (float64, float64, error) {
	return 0, 0, nil
}

func (p DefaultTaxPlugin) ValidateAddress(ctx context.Context, address Address, tenantID string) (bool, error) {
	// Simple validation - just check required fields
	if address.Line1 == "" || address.City == "" || address.PostalCode == "" || address.Country == "" {
		return false, nil
	}
	return true, nil
}

func (p DefaultTaxPlugin) GetTaxExemption(ctx context.Context, taxID string, country string, tenantID string) (bool, string, error) {
	// No exemptions in default implementation
	return false, "", nil
}

func (p DefaultTaxPlugin) Initialize(config map[string]interface{}) error {
	// No configuration needed
	return nil
}

func (p DefaultTaxPlugin) Capabilities() []string {
	return []string{"basic"}
}

// EUTaxPlugin applies EU VAT rules
type EUTaxPlugin struct{}

func (p EUTaxPlugin) Name() string {
	return "eu_vat"
}

func (p EUTaxPlugin) Version() string {
	return "1.0.0"
}

func (p EUTaxPlugin) CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (float64, float64, error) {
	// Simple EU VAT implementation - would be more complex in a real system
	amount := invoice.Amount
	taxRate := 20.0 // Default EU VAT rate
	return amount * taxRate / 100, taxRate, nil
}

func (p EUTaxPlugin) ValidateAddress(ctx context.Context, address Address, tenantID string) (bool, error) {
	// Simple validation for EU addresses
	if address.Line1 == "" || address.City == "" || address.PostalCode == "" || address.Country == "" {
		return false, nil
	}

	// Basic EU country check (incomplete list, would be more thorough in production)
	euCountries := map[string]bool{
		"AT": true, "BE": true, "BG": true, "HR": true, "CY": true, "CZ": true,
		"DK": true, "EE": true, "FI": true, "FR": true, "DE": true, "GR": true,
		"HU": true, "IE": true, "IT": true, "LV": true, "LT": true, "LU": true,
		"MT": true, "NL": true, "PL": true, "PT": true, "RO": true, "SK": true,
		"SI": true, "ES": true, "SE": true,
	}

	if !euCountries[address.Country] {
		return false, nil
	}

	return true, nil
}

func (p EUTaxPlugin) GetTaxExemption(ctx context.Context, taxID string, country string, tenantID string) (bool, string, error) {
	// Basic VAT ID validation (would use VIES in production)
	if len(taxID) < 3 || taxID[:2] != country {
		return false, "", nil
	}

	return true, "EU VAT exemption", nil
}

func (p EUTaxPlugin) Initialize(config map[string]interface{}) error {
	// No configuration needed for demo
	return nil
}

func (p EUTaxPlugin) Capabilities() []string {
	return []string{"eu_vat", "vat_validation", "b2b_exemption"}
}

// ManualTaxPlugin allows manual tax rate configuration
type ManualTaxPlugin struct{}

func (p ManualTaxPlugin) Name() string {
	return "manual"
}

func (p ManualTaxPlugin) Version() string {
	return "1.0.0"
}

func (p ManualTaxPlugin) CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (float64, float64, error) {
	if invoice.TaxRate < 0 || invoice.TaxRate > 100 {
		return 0, 0, NewValidationError("tax_rate", "manual tax rate must be between 0 and 100")
	}

	amount := invoice.Amount
	taxRate := invoice.TaxRate
	return amount * taxRate / 100, taxRate, nil
}

func (p ManualTaxPlugin) ValidateAddress(ctx context.Context, address Address, tenantID string) (bool, error) {
	// Simple validation - just check required fields
	if address.Line1 == "" || address.City == "" || address.PostalCode == "" || address.Country == "" {
		return false, nil
	}
	return true, nil
}

func (p ManualTaxPlugin) GetTaxExemption(ctx context.Context, taxID string, country string, tenantID string) (bool, string, error) {
	// Manual exemption check - always rely on configuration
	return false, "", nil
}

func (p ManualTaxPlugin) Initialize(config map[string]interface{}) error {
	// No initialization needed
	return nil
}

func (p ManualTaxPlugin) Capabilities() []string {
	return []string{"manual_rate", "configurable"}
}

// TaxPlugins is the global registry for all tax plugins.
var TaxPlugins = func() *TaxPluginRegistry {
	r := &TaxPluginRegistry{
		plugins: make(map[string]TaxPlugin),
	}
	r.Register(DefaultTaxPlugin{})
	r.Register(EUTaxPlugin{})
	r.Register(ManualTaxPlugin{})
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

// Address represents a billing or tax address
type Address struct {
	ID          string `json:"id"`
	Line1       string `json:"line1"`
	Line2       string `json:"line2,omitempty"`
	City        string `json:"city"`
	State       string `json:"state"`
	PostalCode  string `json:"postal_code"`
	Country     string `json:"country"`
	AddressType string `json:"address_type"`
	Validated   bool   `json:"validated"`
	TenantID    string `json:"tenant_id"`
}
