package payment

import (
	"time"

	braintree "github.com/braintree-go/braintree-go"
	paypal "github.com/plutov/paypal/v4"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

const (
	PaymentMethodCard      = "card"
	PaymentMethodApplePay  = "apple_pay"
	PaymentMethodGooglePay = "google_pay"
)

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

type DisputeService struct {
	Store       DisputeStoreInterface
	Notify      security_management.NotificationService
	AuditLogger security_management.AuditLogger
}

// DisputeEvidence represents an evidence file or submission for a dispute
// All fields required for audit, provider sync, and admin UI
// ProviderStatus: pending, submitted, accepted, rejected, error
// ProviderResponse: provider-specific response or error

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
