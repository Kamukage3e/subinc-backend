package payment

import (
	"context"
	"time"
)

// PaymentProvider defines the interface for all payment providers (Stripe, PayPal, Braintree, etc).
// Implementations must support multiple payment methods (card, apple pay, google pay) via the Source field in CreatePaymentRequest.
type PaymentProvider interface {
	CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*PaymentResult, error)
	RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error)
	GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error)
}

// StoreInterface abstracts Store for testability and dynamic provider lookup
// Must be implemented by Store
type StoreInterface interface {
	GetTenantPaymentProviderConfig(ctx context.Context, tenantID string) (*TenantPaymentProviderConfig, error)
	GetTenantProviderSecret(ctx context.Context, tenantID, provider string) (map[string]string, error)
	SavePayment(ctx context.Context, p *PaymentResult) error
	GetPaymentResult(ctx context.Context, paymentID string) (*PaymentResult, error)
	// Dunning methods
	ListFailedPayments(ctx context.Context, tenantID string) ([]*FailedPayment, error)
	GetDunningConfig(ctx context.Context, tenantID string) (*DunningConfig, error)
	UpdateDunningState(ctx context.Context, paymentID, state string, attempts int) error
	UpdateDunningAttempt(ctx context.Context, paymentID string, lastAttempt time.Time, attempts int) error
	// Billing event processing
	UpdateInvoiceStatus(ctx context.Context, invoiceID, status string) error
	MarkPaymentsPaidForInvoice(ctx context.Context, invoiceID string) error
	UpdatePaymentStatus(ctx context.Context, paymentID, status string) error

	// Plugin management
	SavePaymentPluginConfig(ctx context.Context, config *PaymentPluginConfig) error
	GetPaymentPluginConfig(ctx context.Context, tenantID, pluginName string) (*PaymentPluginConfig, error)
	ListPaymentPluginConfigs(ctx context.Context, tenantID string) ([]*PaymentPluginConfig, error)
	DisablePaymentPlugin(ctx context.Context, tenantID, pluginName string) error
	GetDefaultPaymentPlugin(ctx context.Context, tenantID string) (*PaymentPluginConfig, error)

	// Transaction reporting
	GetTransactionReport(ctx context.Context, tenantID string, startDate, endDate time.Time, includeDailyTotals bool) (*TransactionReport, error)
	GetPaymentMethodReport(ctx context.Context, tenantID string, startDate, endDate time.Time) (map[string]int, error)
	GetTransactionVolume(ctx context.Context, tenantID string, startDate, endDate time.Time) (float64, int, error)

	// Customer portal
	GetStripeCustomerID(ctx context.Context, accountID string) (string, error)
}

// DisputeDataStoreInterface abstracts dispute and evidence storage for testability and multi-tenant support
// All methods must be robust, multi-tenant, and audit-friendly
// Dispute methods
// Evidence methods
type DisputeDataStoreInterface interface {
	// Dispute methods
	CreateDispute(ctx context.Context, d *Dispute) error
	GetDispute(ctx context.Context, id string) (*Dispute, error)
	ListDisputes(ctx context.Context, tenantID, paymentID string, status DisputeStatus, page, pageSize int) ([]*Dispute, error)
	UpdateDisputeStatus(ctx context.Context, id string, status DisputeStatus, evidenceSubmitted *time.Time) error

	// Add this for soft delete
	DeleteDispute(ctx context.Context, id string) error

	// Dispute evidence methods
	CreateDisputeEvidence(ctx context.Context, e *DisputeEvidence) error
	GetDisputeEvidence(ctx context.Context, evidenceID string) (*DisputeEvidence, error)
	ListDisputeEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*DisputeEvidence, error)
	UpdateDisputeEvidenceStatus(ctx context.Context, evidenceID, providerStatus, providerResponse string) error

	// Add this for soft delete of evidence
	DeleteDisputeEvidence(ctx context.Context, evidenceID string) error
}

// PaymentService manages payment operations
type PaymentService interface {
	CreatePayment(ctx context.Context, input Payment) (Payment, error)
	UpdatePayment(ctx context.Context, input Payment) (Payment, error)
	GetPayment(ctx context.Context, id string) (Payment, error)
	ListPayments(ctx context.Context, invoiceID string, page, pageSize int) ([]Payment, error)
	GetPaymentByIdempotencyKey(ctx context.Context, idempotencyKey string) (Payment, error)
	RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error)
	GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error)
}

// RefundService manages refund operations
type RefundService interface {
	CreateRefund(ctx context.Context, input Refund) (Refund, error)
	UpdateRefund(ctx context.Context, input Refund) (Refund, error)
	DeleteRefund(ctx context.Context, id string) error
	GetRefund(ctx context.Context, id string) (Refund, error)
	ListRefunds(ctx context.Context, paymentID, invoiceID, status string, page, pageSize int) ([]Refund, error)
}

// PaymentMethodService manages payment methods
type PaymentMethodService interface {
	CreatePaymentMethod(ctx context.Context, input PaymentMethod, data map[string]string) (PaymentMethod, error)
	UpdatePaymentMethod(ctx context.Context, input PaymentMethod) (PaymentMethod, error)
	PatchPaymentMethod(ctx context.Context, id string, setDefault *bool, status string) error
	DeletePaymentMethod(ctx context.Context, id string) error
	GetPaymentMethod(ctx context.Context, id string) (PaymentMethod, error)
	ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]PaymentMethod, error)
}

// DisputeEvidenceService handles evidence upload, provider sync, audit, and admin endpoints
// All methods robust, multi-tenant, audit-logged

type ManualRefundService interface {
	CreateManualRefund(ctx context.Context, refund Refund) (Refund, error)
}

// PaymentPlugin defines a hot-pluggable interface for payment providers
// Each implementation can be dynamically loaded and configured at runtime
type PaymentPlugin interface {
	// Plugin identity
	Name() string    // Unique name for the payment plugin (e.g., "stripe", "paypal")
	Version() string // Version in semver format

	// Core payment operations
	Create(ctx context.Context, p Payment) (Payment, error)                        // Process a payment
	Refund(ctx context.Context, paymentID string, amount float64) (Payment, error) // Process a refund
	Update(ctx context.Context, p Payment) (Payment, error)                        // Update payment status
	GetStatus(ctx context.Context, paymentID string) (string, error)               // Check payment status

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error                                // Initialize plugin with configuration
	Capabilities() []string                                                        // Return supported features (e.g., "cards", "ach", "crypto")
	ValidatePaymentMethod(ctx context.Context, method PaymentMethod) (bool, error) // Validate if payment method is supported

	// Webhook handling
	HandleWebhook(ctx context.Context, payload []byte, signature string) (interface{}, error) // Process provider webhook events
}

// PluginService manages payment plugin operations
type PluginService interface {
	ListPaymentPlugins(ctx context.Context) ([]string, error)
	GetPaymentPlugin(ctx context.Context, name string) (PaymentPlugin, error)
	SavePaymentPluginConfig(ctx context.Context, config *PaymentPluginConfig) error
	DisablePaymentPlugin(ctx context.Context, tenantID, pluginName string) error
}

// TransactionReportService manages transaction reporting
type TransactionReportService interface {
	GetTransactionReport(ctx context.Context, tenantID string, startDate, endDate time.Time, includeDailyTotals bool) (*TransactionReport, error)
	GetPaymentMethodReport(ctx context.Context, tenantID string, startDate, endDate time.Time) (map[string]int, error)
	GetTransactionVolume(ctx context.Context, tenantID string, startDate, endDate time.Time) (float64, int, error)
}
