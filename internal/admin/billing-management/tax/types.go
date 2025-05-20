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

// NorthAmericaTaxPlugin handles tax calculation for US and Canada
type NorthAmericaTaxPlugin struct {
	// State/province tax rates - could be loaded from DB in real implementation
	usTaxRates map[string]float64
	caTaxRates map[string]float64
	// Cache for tax exemptions
	exemptions map[string]bool
}

func NewNorthAmericaTaxPlugin() *NorthAmericaTaxPlugin {
	p := &NorthAmericaTaxPlugin{
		usTaxRates: map[string]float64{
			"AL": 4.0,   // Alabama
			"AK": 0.0,   // Alaska
			"AZ": 5.6,   // Arizona
			"AR": 6.5,   // Arkansas
			"CA": 7.25,  // California
			"CO": 2.9,   // Colorado
			"CT": 6.35,  // Connecticut
			"DE": 0.0,   // Delaware
			"FL": 6.0,   // Florida
			"GA": 4.0,   // Georgia
			"HI": 4.0,   // Hawaii
			"ID": 6.0,   // Idaho
			"IL": 6.25,  // Illinois
			"IN": 7.0,   // Indiana
			"IA": 6.0,   // Iowa
			"KS": 6.5,   // Kansas
			"KY": 6.0,   // Kentucky
			"LA": 4.45,  // Louisiana
			"ME": 5.5,   // Maine
			"MD": 6.0,   // Maryland
			"MA": 6.25,  // Massachusetts
			"MI": 6.0,   // Michigan
			"MN": 6.875, // Minnesota
			"MS": 7.0,   // Mississippi
			"MO": 4.225, // Missouri
			"MT": 0.0,   // Montana
			"NE": 5.5,   // Nebraska
			"NV": 6.85,  // Nevada
			"NH": 0.0,   // New Hampshire
			"NJ": 6.625, // New Jersey
			"NM": 5.125, // New Mexico
			"NY": 4.0,   // New York
			"NC": 4.75,  // North Carolina
			"ND": 5.0,   // North Dakota
			"OH": 5.75,  // Ohio
			"OK": 4.5,   // Oklahoma
			"OR": 0.0,   // Oregon
			"PA": 6.0,   // Pennsylvania
			"RI": 7.0,   // Rhode Island
			"SC": 6.0,   // South Carolina
			"SD": 4.5,   // South Dakota
			"TN": 7.0,   // Tennessee
			"TX": 6.25,  // Texas
			"UT": 6.1,   // Utah
			"VT": 6.0,   // Vermont
			"VA": 5.3,   // Virginia
			"WA": 6.5,   // Washington
			"WV": 6.0,   // West Virginia
			"WI": 5.0,   // Wisconsin
			"WY": 4.0,   // Wyoming
			"DC": 6.0,   // District of Columbia
		},
		caTaxRates: map[string]float64{
			"AB": 5.0,    // Alberta (GST only)
			"BC": 12.0,   // British Columbia (GST + PST)
			"MB": 12.0,   // Manitoba (GST + PST)
			"NB": 15.0,   // New Brunswick (HST)
			"NL": 15.0,   // Newfoundland and Labrador (HST)
			"NT": 5.0,    // Northwest Territories (GST only)
			"NS": 15.0,   // Nova Scotia (HST)
			"NU": 5.0,    // Nunavut (GST only)
			"ON": 13.0,   // Ontario (HST)
			"PE": 15.0,   // Prince Edward Island (HST)
			"QC": 14.975, // Quebec (GST + QST)
			"SK": 11.0,   // Saskatchewan (GST + PST)
			"YT": 5.0,    // Yukon (GST only)
		},
		exemptions: make(map[string]bool),
	}
	return p
}

func (p NorthAmericaTaxPlugin) Name() string {
	return "north_america"
}

func (p NorthAmericaTaxPlugin) Version() string {
	return "1.0.0"
}

func (p NorthAmericaTaxPlugin) CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (float64, float64, error) {
	// Get tax info for the tenant (would come from database in real implementation)
	var taxInfo TaxInfo
	// In a real implementation, we would look up tax info for this account/tenant

	// Set default country from invoice if we don't have it
	country := ""

	// Try to extract country info from either tax info or account
	if account.TenantID != "" {
		// Get TaxInfo from database by TenantID (simulated here)
		taxInfo = TaxInfo{
			TenantID: account.TenantID,
			Country:  "", // Would be populated from DB
			Region:   "", // Would be populated from DB
			TaxID:    "", // Would be populated from DB
		}
		country = taxInfo.Country
	}

	// Default to invoice currency country code if needed
	if country == "" {
		if invoice.Currency == "USD" {
			country = "US"
		} else if invoice.Currency == "CAD" {
			country = "CA"
		}
	}

	// Lookup region/state/province based on country
	region := taxInfo.Region

	// Determine applicable tax rate based on location
	var taxRate float64
	switch country {
	case "US":
		if rate, ok := p.usTaxRates[region]; ok && region != "" {
			taxRate = rate
		} else {
			// Default US tax rate if state not found
			taxRate = 0.0 // Most digital services don't have federal sales tax
		}
	case "CA":
		if rate, ok := p.caTaxRates[region]; ok && region != "" {
			taxRate = rate
		} else {
			// Default Canadian tax rate (GST only)
			taxRate = 5.0
		}
	default:
		// For other countries, no tax by default
		// In a real implementation, would check for other countries or return an error
		taxRate = 0.0
	}

	// Check for tax exemption if there's a tax ID
	taxID := taxInfo.TaxID
	if taxID != "" {
		if exempt, ok := p.exemptions[taxID]; ok && exempt {
			taxRate = 0.0
		}
	}

	// Calculate tax amount
	amount := invoice.Amount
	taxAmount := amount * taxRate / 100.0

	return taxAmount, taxRate, nil
}

func (p NorthAmericaTaxPlugin) ValidateAddress(ctx context.Context, address Address, tenantID string) (bool, error) {
	// Basic address validation
	if address.Line1 == "" || address.City == "" || address.PostalCode == "" || address.Country == "" {
		return false, nil
	}

	// Validate country
	validCountries := map[string]bool{"US": true, "CA": true}
	if !validCountries[address.Country] {
		return false, nil
	}

	// Validate postal code format
	if address.Country == "US" {
		// Simple US ZIP validation (5 digits or 5+4)
		if len(address.PostalCode) != 5 && len(address.PostalCode) != 10 {
			return false, nil
		}
	} else if address.Country == "CA" {
		// Simple Canada postal code validation (A1A 1A1 format)
		if len(address.PostalCode) != 6 && len(address.PostalCode) != 7 {
			return false, nil
		}
	}

	return true, nil
}

func (p NorthAmericaTaxPlugin) GetTaxExemption(ctx context.Context, taxID string, country string, tenantID string) (bool, string, error) {
	// Check if tax ID is in exemptions list
	if exempt, ok := p.exemptions[taxID]; ok && exempt {
		if country == "US" {
			return true, "US Tax Exemption", nil
		}
		if country == "CA" {
			return true, "Canadian Tax Exemption", nil
		}
	}

	return false, "", nil
}

func (p NorthAmericaTaxPlugin) Initialize(config map[string]interface{}) error {
	// For the non-pointer receiver, we can't mutate the state directly
	// In a real implementation, we would have a proper initialization process
	// For now, we'll just return success since we initialize in the constructor
	return nil
}

func (p NorthAmericaTaxPlugin) Capabilities() []string {
	return []string{"us_sales_tax", "ca_gst_hst", "exemption_certificates", "address_validation"}
}

// TaxPlugins is the global registry for all tax plugins.
var TaxPlugins = func() *TaxPluginRegistry {
	r := &TaxPluginRegistry{
		plugins: make(map[string]TaxPlugin),
	}
	r.Register(DefaultTaxPlugin{})
	r.Register(EUTaxPlugin{})
	r.Register(ManualTaxPlugin{})

	// Initialize North America tax plugin with proper data
	naPlugin := NewNorthAmericaTaxPlugin()
	// The plugin instance is properly initialized with constructor
	r.Register(*naPlugin) // Use value type since our methods use value receiver

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
