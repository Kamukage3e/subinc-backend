package payment

import (
	"reflect"
	"time"

	braintree "github.com/braintree-go/braintree-go"
	"github.com/jackc/pgx/v5/pgxpool"
	paypal "github.com/plutov/paypal/v4"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

const (
	PaymentMethodCard      = "card"
	PaymentMethodApplePay  = "apple_pay"
	PaymentMethodGooglePay = "google_pay"
)

// DisputeHandler handles dispute endpoints
// Implements RESTful dispute and evidence management
// All methods robust, audit-logged, and RBAC-checked

type PostgresStore struct {
	DB *pgxpool.Pool
}

// CreatePaymentRequest represents a payment creation request (card, Apple Pay, Google Pay, etc).
type CreatePaymentRequest struct {
	Amount      float64           `json:"amount"`
	Currency    string            `json:"currency"`
	Source      string            `json:"source"` // card token, Apple Pay token, etc
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RefundPaymentRequest represents a refund request.
type RefundPaymentRequest struct {
	PaymentID string  `json:"payment_id"`
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency"`
	Reason    string  `json:"reason,omitempty"`
}

// PaymentResult represents the result of a payment or refund.
type PaymentResult struct {
	PaymentID string      `json:"payment_id"`
	Status    string      `json:"status"`
	Amount    float64     `json:"amount"`
	Currency  string      `json:"currency"`
	CreatedAt time.Time   `json:"created_at"`
	Provider  string      `json:"provider"`
	Raw       interface{} `json:"raw,omitempty"` // provider-specific response
}

// PaymentStatus represents the status of a payment.
type PaymentStatus struct {
	PaymentID string      `json:"payment_id"`
	Status    string      `json:"status"`
	Amount    float64     `json:"amount"`
	Currency  string      `json:"currency"`
	UpdatedAt time.Time   `json:"updated_at"`
	Provider  string      `json:"provider"`
	Raw       interface{} `json:"raw,omitempty"`
}

// Payment represents a payment for an invoice
// All fields are required for SaaS billing and auditability
// Status: pending, completed, failed, refunded
// Method: card, bank, etc.
// Metadata: JSON-encoded for extensibility
type Payment struct {
	ID               string    `json:"id"`
	InvoiceID        string    `json:"invoice_id"`
	Amount           float64   `json:"amount"`
	Currency         string    `json:"currency"` // ISO 4217, e.g. USD
	OriginalAmount   float64   `json:"original_amount,omitempty"`
	OriginalCurrency string    `json:"original_currency,omitempty"`
	Status           string    `json:"status"`
	Method           string    `json:"method"`
	Last4            string    `json:"last4"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Metadata         string    `json:"metadata"`
	PluginName       string    `json:"plugin_name"`
}

func (p *Payment) Validate() *Error {
	if p.InvoiceID == "" {
		return NewValidationError("invoice_id", "must not be empty")
	}
	if p.Amount < 0 {
		return NewValidationError("amount", "must be non-negative")
	}
	if p.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	if p.Method == "" {
		return NewValidationError("method", "must not be empty")
	}
	if len(p.Last4) != 4 {
		return NewValidationError("last4", "must be 4 characters")
	}
	return nil
}

// Refund represents a refund for a payment/invoice
// All fields are required for SaaS billing and auditability
// Status: pending, processed, failed, reversed
// Metadata: JSON-encoded for extensibility
type Refund struct {
	ID               string    `json:"id"`
	PaymentID        string    `json:"payment_id"`
	InvoiceID        string    `json:"invoice_id,omitempty"`
	Amount           float64   `json:"amount"`
	Currency         string    `json:"currency"`
	OriginalAmount   float64   `json:"original_amount,omitempty"`
	OriginalCurrency string    `json:"original_currency,omitempty"`
	Reason           string    `json:"reason"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Metadata         string    `json:"metadata"`
}

func (r *Refund) Validate() *Error {
	if r.PaymentID == "" {
		return NewValidationError("payment_id", "must not be empty")
	}
	if r.Amount <= 0 {
		return NewValidationError("amount", "must be greater than zero")
	}
	if r.Currency == "" {
		return NewValidationError("currency", "must not be empty")
	}
	if r.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}

// PaymentMethod represents a PCI-compliant payment method for an account
// All fields are required for SaaS billing and auditability
// Status: active, inactive, expired, failed
// Token: PCI token reference, never raw PAN
// TokenProvider: e.g., stripe, adyen, aws_kms
// Metadata: JSON-encoded for extensibility
// IsDefault: whether this is the default payment method for the account
type PaymentMethod struct {
	ID            string    `json:"id"`
	AccountID     string    `json:"account_id"`
	Type          string    `json:"type"`
	Provider      string    `json:"provider"`
	Last4         string    `json:"last4"`
	ExpMonth      int       `json:"exp_month"`
	ExpYear       int       `json:"exp_year"`
	IsDefault     bool      `json:"is_default"`
	Status        string    `json:"status"`
	Token         string    `json:"token"`
	TokenProvider string    `json:"token_provider"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Metadata      string    `json:"metadata"`
}

func (p *PaymentMethod) Validate() *Error {
	if p.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if p.Type == "" {
		return NewValidationError("type", "must not be empty")
	}
	if p.Provider == "" {
		return NewValidationError("provider", "must not be empty")
	}
	if p.Last4 == "" || len(p.Last4) != 4 {
		return NewValidationError("last4", "must be 4 characters")
	}
	if p.ExpMonth < 1 || p.ExpMonth > 12 {
		return NewValidationError("exp_month", "must be between 1 and 12")
	}
	if p.ExpYear < time.Now().Year() {
		return NewValidationError("exp_year", "must not be in the past")
	}
	if p.Token == "" {
		return NewValidationError("token", "must not be empty")
	}
	if p.TokenProvider == "" {
		return NewValidationError("token_provider", "must not be empty")
	}
	return nil
}

// Error type for validation and domain errors
type Error struct {
	Code    string
	Message string
	Field   string
	Err     error
}

func NewValidationError(field, msg string) *Error {
	return &Error{
		Code:    "VALIDATION_ERROR",
		Message: msg,
		Field:   field,
	}
}

func (e *Error) Error() string {
	if e.Field != "" {
		return e.Code + ": " + e.Message + " (" + e.Field + ")"
	}
	return e.Code + ": " + e.Message
}

// ErrorFromBilling converts a billing_management.Error to a payment.Error
func ErrorFromBilling(err error) *Error {
	if err == nil {
		return nil
	}

	// Check if it's already a payment.Error
	if pErr, ok := err.(*Error); ok {
		return pErr
	}

	// Try to convert from billing_management.Error
	// This avoids importing billing_management to prevent circular deps
	// We use type assertion on the interface{} to check fields

	// Use reflection to extract fields
	errValue := reflect.ValueOf(err)
	if errValue.Kind() == reflect.Ptr && !errValue.IsNil() {
		errValue = errValue.Elem()
		if errValue.Kind() == reflect.Struct {
			// Try to extract Code, Message, Field
			codeField := errValue.FieldByName("Code")
			messageField := errValue.FieldByName("Message")
			fieldField := errValue.FieldByName("Field")

			if codeField.IsValid() && messageField.IsValid() && fieldField.IsValid() {
				return &Error{
					Code:    codeField.String(),
					Message: messageField.String(),
					Field:   fieldField.String(),
					Err:     err,
				}
			}
		}
	}

	// Fallback - wrap the generic error
	return &Error{
		Code:    "INTERNAL_ERROR",
		Message: err.Error(),
		Err:     err,
	}
}

type TenantPaymentProviderConfig struct {
	TenantID  string    `json:"tenant_id"`
	Provider  string    `json:"provider"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PaypalProvider struct {
	Client      *paypal.Client
	AuditLogger security_management.AuditLogger
	Store       StoreInterface
}

type StripeProvider struct {
	APIKey      string
	AuditLogger security_management.AuditLogger
	Store       StoreInterface
	Notify      security_management.NotificationService
}

type BraintreeProvider struct {
	Client      *braintree.Braintree
	AuditLogger security_management.AuditLogger
	Store       StoreInterface
}

// ProviderRegistry holds registered payment providers by name.
type ProviderRegistry struct {
	providers map[string]PaymentProvider
}

var PaymentProviders = &ProviderRegistry{}

// TenantProviderSecret stores per-tenant provider credentials/config as JSON
// This enables dynamic, per-tenant provider instantiation
// Table: tenant_provider_secret (tenant_id, provider, config_json, updated_at)
type TenantProviderSecret struct {
	TenantID  string            `json:"tenant_id"`
	Provider  string            `json:"provider"`
	Config    map[string]string `json:"config"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// DunningConfig holds per-tenant dunning policy
// RetryIntervals is a slice of durations for each retry attempt (e.g. [1h, 24h, 72h])
type DunningConfig struct {
	MaxAttempts    int             `json:"max_attempts"`
	RetryIntervals []time.Duration `json:"retry_intervals"`
}

// FailedPayment represents a payment that failed and is subject to dunning
// DunningState: "pending", "retrying", "recovered", "failed"
type FailedPayment struct {
	ID                 string    `json:"id"`
	InvoiceID          string    `json:"invoice_id"`
	DunningAttempts    int       `json:"dunning_attempts"`
	DunningState       string    `json:"dunning_state"`
	LastDunningAttempt time.Time `json:"last_dunning_attempt"`
}

// DisputeStatus: open, won, lost, evidence_required, under_review, closed
type DisputeStatus string

const (
	DisputeStatusOpen             DisputeStatus = "open"
	DisputeStatusWon              DisputeStatus = "won"
	DisputeStatusLost             DisputeStatus = "lost"
	DisputeStatusEvidenceRequired DisputeStatus = "evidence_required"
	DisputeStatusUnderReview      DisputeStatus = "under_review"
	DisputeStatusClosed           DisputeStatus = "closed"
)

// Dispute represents a payment dispute/chargeback event
// All fields required for audit, notification, and provider sync
type Dispute struct {
	ID                string        `json:"id"`
	PaymentID         string        `json:"payment_id"`
	TenantID          string        `json:"tenant_id"`
	Provider          string        `json:"provider"`
	Status            DisputeStatus `json:"status"`
	Reason            string        `json:"reason"`
	Amount            float64       `json:"amount"`
	Currency          string        `json:"currency"`
	EvidenceDue       *time.Time    `json:"evidence_due,omitempty"`
	EvidenceSubmitted *time.Time    `json:"evidence_submitted,omitempty"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	Raw               interface{}   `json:"raw,omitempty"`
}

type DisputeEvidence struct {
	ID               string      `json:"id"`
	DisputeID        string      `json:"dispute_id"`
	TenantID         string      `json:"tenant_id"`
	FileURL          string      `json:"file_url"`
	FileName         string      `json:"file_name"`
	FileType         string      `json:"file_type"`
	UploadedBy       string      `json:"uploaded_by"`
	UploadedAt       time.Time   `json:"uploaded_at"`
	ProviderStatus   string      `json:"provider_status"`
	ProviderResponse string      `json:"provider_response"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	Raw              interface{} `json:"raw,omitempty"`
}

// PaymentPlugin defines a hot-pluggable interface for payment logic.

// PaymentPluginRegistry is a registry for payment plugins
// It provides a way to register and retrieve payment plugins at runtime
type PaymentPluginRegistry struct {
	plugins map[string]PaymentPlugin
}

// Global registry for payment plugins
var PaymentPlugins = &PaymentPluginRegistry{
	plugins: make(map[string]PaymentPlugin),
}

// Register adds a payment plugin to the registry
func (r *PaymentPluginRegistry) Register(plugin PaymentPlugin) {
	if plugin == nil {
		return
	}
	name := plugin.Name()
	if name == "" {
		return
	}
	r.plugins[name] = plugin
}

// Lookup retrieves a payment plugin by name
func (r *PaymentPluginRegistry) Lookup(name string) (PaymentPlugin, bool) {
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// List returns all registered payment plugin names
func (r *PaymentPluginRegistry) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// Unregister removes a payment plugin from the registry
func (r *PaymentPluginRegistry) Unregister(name string) {
	delete(r.plugins, name)
}

// PaymentPluginConfig stores tenant-specific payment plugin configuration
type PaymentPluginConfig struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	PluginName string                 `json:"plugin_name"`
	Config     map[string]interface{} `json:"config"`
	Enabled    bool                   `json:"enabled"`
	Default    bool                   `json:"default"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}
