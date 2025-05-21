package billing_management

import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/tax"
)

type InvoiceService interface {
	CreateInvoice(ctx context.Context, input Invoice) (Invoice, error)
	UpdateInvoice(input Invoice) (Invoice, error)
	GetInvoice(id string) (Invoice, error)
	ListInvoices(accountID, status string, page, pageSize int) ([]Invoice, error)
	GetInvoicePreview(accountID string) (Invoice, error)
	GetBillingConfig() (map[string]interface{}, error)
	SetBillingConfig(input map[string]interface{}) error
	DeleteInvoice(id string) error
}

// InvoiceExportService handles invoice file generation and export
type InvoiceExportService interface {
	DownloadInvoicePDF(ctx context.Context, invoiceID string) ([]byte, error)
	CreateInvoiceWithFeesAndTax(ctx context.Context, invoice Invoice, fixedFee, percentFee, taxRate float64) (Invoice, error)
}

type PaymentService interface {
	CreatePayment(input payment.Payment) (payment.Payment, error)
	UpdatePayment(input payment.Payment) (payment.Payment, error)
	GetPayment(id string) (payment.Payment, error)
	ListPayments(invoiceID string, page, pageSize int) ([]payment.Payment, error)
	GetPaymentByIdempotencyKey(idempotencyKey string) (payment.Payment, error)

	RefundPayment(ctx context.Context, req *payment.RefundPaymentRequest) (*payment.PaymentResult, error)
	GetPaymentStatus(ctx context.Context, paymentID string) (*payment.PaymentStatus, error)
}

type RefundService interface {
	CreateRefund(input payment.Refund) (payment.Refund, error)
	UpdateRefund(id string) error
	DeleteRefund(id string) error
	GetRefund(id string) (payment.Refund, error)
	ListRefunds(paymentID, invoiceID, status string, page, pageSize int) ([]payment.Refund, error)
}

type PaymentMethodService interface {
	CreatePaymentMethod(input payment.PaymentMethod, data map[string]string) (payment.PaymentMethod, error)
	UpdatePaymentMethod(input payment.PaymentMethod) (payment.PaymentMethod, error)
	PatchPaymentMethod(id string, setDefault *bool, status string) error
	DeletePaymentMethod(id string) error
	GetPaymentMethod(id string) (payment.PaymentMethod, error)
	ListPaymentMethods(accountID, status string, page, pageSize int) ([]payment.PaymentMethod, error)
}

type WebhookEventService interface {
	CreateWebhookEvent(input WebhookEvent) (WebhookEvent, error)
	UpdateWebhookEvent(input WebhookEvent) (WebhookEvent, error)
	DeleteWebhookEvent(id string) error
	GetWebhookEvent(id string) (WebhookEvent, error)
	ListWebhookEvents(accountID, status string, page, pageSize int) ([]WebhookEvent, error)
}

type InvoiceAdjustmentService interface {
	CreateInvoiceAdjustment(input InvoiceAdjustment) (InvoiceAdjustment, error)
	UpdateInvoiceAdjustment(input InvoiceAdjustment) (InvoiceAdjustment, error)
	DeleteInvoiceAdjustment(id string) error
	GetInvoiceAdjustment(id string) (InvoiceAdjustment, error)
	ListInvoiceAdjustments(invoiceID string, page, pageSize int) ([]InvoiceAdjustment, error)
	ApplyCreditsToInvoice(accountID, invoiceID string) ([]InvoiceAdjustment, error)
}

// ManualAdjustmentService handles manual invoice adjustments
// All methods must be robust, user-friendly, and never leak sensitive info
type ManualAdjustmentService interface {
	CreateManualAdjustment(accountID, reason string, amount float64, currency string) error
}

// ManualRefundService handles manual refunds
// All methods must be robust, user-friendly, and never leak sensitive info

// AccountActionService handles account-level actions (e.g., suspend, activate, custom ops)
// All methods must be robust, user-friendly, and never leak sensitive info
type AccountActionService interface {
	PerformAccountAction(accountID, action string) error
}

type WebhookSubscriptionService interface {
	CreateWebhookSubscription(url, secret, description string, events []string) error
	DeleteWebhookSubscription(id string) error
	ListWebhookSubscriptions(tenantID string, page, pageSize int) ([]WebhookSubscription, error)
	TestWebhookSubscription(id string, eventType string, payload map[string]interface{}) error
	GetWebhookSubscription(id string) (WebhookSubscription, error)
	UpdateWebhookSubscription(id string, url, secret string, events []string, status string) error
	GetWebhookDeliveryLogs(subscriptionID string, page, pageSize int) ([]WebhookDeliveryLog, error)
	RetryWebhookDelivery(deliveryID string) error
}

type TenantCurrencyService interface {
	SetTenantCurrency(ctx context.Context, tenantID, currency string) (TenantCurrency, error)
	GetTenantCurrency(ctx context.Context, tenantID string) (TenantCurrency, error)
}

// All audit logging must use AuditLogger for decoupling and optionality.
type BillingAuditLogger interface {
	LogBillingEvent(event string, actor string, target string, details string)
}

// ReportService defines interfaces for generating financial reports
type ReportService interface {
	GetRevenueReport(ctx context.Context) (map[string]interface{}, error)
	GetARReport(ctx context.Context) (map[string]interface{}, error)
	GetChurnReport(ctx context.Context) (map[string]interface{}, error)
}

// DunningService handles payment collection retry operations
type DunningService interface {
	GetDunningConfig(ctx context.Context, tenantID string) (*DunningConfig, error)
	UpdateDunningConfig(ctx context.Context, tenantID string, config *DunningConfig) error
	ManualRetryDunning(ctx context.Context, invoiceID string) error
	GetDunningEvents(ctx context.Context, invoiceID string, page, pageSize int) ([]DunningEvent, error)
	GetDunningDashboard(ctx context.Context, tenantID string) (*DunningDashboard, error)
}

// DisputeServiceInterface defines admin dispute management contract
// (moved from types.go for consistency)
type DisputeServiceInterface interface {
	ListDisputes(ctx context.Context, tenantID, paymentID string, status payment.DisputeStatus, page, pageSize int) ([]*payment.Dispute, error)
	GetDispute(ctx context.Context, disputeID string) (*payment.Dispute, error)
	UpdateDisputeStatus(ctx context.Context, disputeID string, status payment.DisputeStatus, evidenceSubmitted *time.Time) error
}

type DisputeEvidenceServiceInterface interface {
	UploadEvidence(ctx context.Context, e *payment.DisputeEvidence) error
	ListEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*payment.DisputeEvidence, error)
	GetEvidence(ctx context.Context, evidenceID string) (*payment.DisputeEvidence, error)
	UpdateEvidenceStatus(ctx context.Context, evidenceID, providerStatus, providerResponse string) error
}

// InvoicePlugin defines a hot-pluggable interface for invoice logic.
// Plugins can be added, configured, and removed at runtime without server restarts.
type InvoicePlugin interface {
	Name() string    // Unique identifier for the plugin
	Version() string // Plugin version in semver format (e.g., "1.0.0")

	// Core invoice operations
	Create(ctx context.Context, inv Invoice) (Invoice, error)    // Create a new invoice
	Update(ctx context.Context, inv Invoice) (Invoice, error)    // Update an existing invoice
	Calculate(ctx context.Context, inv Invoice) (Invoice, error) // Calculate invoice details (taxes, fees, etc.)
	Export(ctx context.Context, inv Invoice) ([]byte, error)     // Export invoice to a format (PDF, CSV, etc.)

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize plugin with configuration parameters
	Capabilities() []string                         // Return list of supported capabilities/features
}

// PaymentPlugin defines a hot-pluggable interface for payment processing.
// Allows runtime integration with multiple payment providers without code changes.
type PaymentPlugin interface {
	Name() string    // Unique identifier for the plugin
	Version() string // Plugin version in semver format (e.g., "1.0.0")

	// Core payment operations
	ProcessPayment(ctx context.Context, payment payment.Payment) (*payment.PaymentResult, error) // Process a payment transaction
	RefundPayment(ctx context.Context, refund payment.Refund) (*payment.PaymentResult, error)    // Process a refund
	ValidatePaymentMethod(ctx context.Context, method payment.PaymentMethod) (bool, error)       // Validate payment method details
	HandleWebhook(ctx context.Context, payload []byte, signature string) (WebhookEvent, error)   // Process provider webhooks

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize plugin with configuration parameters
	Capabilities() []string                         // Return list of supported payment methods, currencies, etc.
}

// TaxPlugin defines a hot-pluggable interface for tax calculation.
// Enables runtime integration with multiple tax providers for global compliance.
type TaxPlugin interface {
	Name() string    // Unique identifier for the plugin
	Version() string // Plugin version in semver format (e.g., "1.0.0")

	// Core tax operations
	CalculateTax(ctx context.Context, invoice tax.Invoice, account tax.Account, tenantID string) (float64, float64, error) // Calculate tax amount and rate
	ValidateAddress(ctx context.Context, address tax.Address, tenantID string) (bool, error)                               // Validate address for tax purposes
	GetTaxExemption(ctx context.Context, taxID string, country string, tenantID string) (bool, string, error)              // Check if tax ID provides exemption

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize plugin with configuration parameters
	Capabilities() []string                         // Return list of supported tax jurisdictions, tax types, etc.
}

// SubscriptionPlugin defines a hot-pluggable interface for subscription management
// Enables runtime integration with multiple subscription providers
type SubscriptionPlugin interface {
	Name() string    // Unique identifier for the plugin
	Version() string // Plugin version in semver format (e.g., "1.0.0")

	// Core subscription operations
	Create(ctx context.Context, subscription interface{}) (interface{}, error)
	Update(ctx context.Context, subscription interface{}) (interface{}, error)
	Cancel(ctx context.Context, subscriptionID string) error
	Resume(ctx context.Context, subscriptionID string) error
	ChangePlan(ctx context.Context, subscriptionID string, planID string) error

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize plugin with configuration parameters
	Capabilities() []string                         // Return list of supported capabilities/features
}

// FeePlugin defines a hot-pluggable interface for fee calculation
// Enables runtime integration with multiple fee processors
type FeePlugin interface {
	Name() string    // Unique identifier for the plugin
	Version() string // Plugin version in semver format (e.g., "1.0.0")

	// Core fee operations
	Calculate(ctx context.Context, invoice interface{}) (interface{}, error) // Calculate fees for an invoice
	Describe(ctx context.Context, fee interface{}) (string, error)           // Get human-readable description

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize plugin with configuration parameters
	Capabilities() []string                         // Return list of supported capabilities/features
}

// AccountPlugin defines a hot-pluggable interface for account management
// Enables runtime integration with multiple account management systems
type AccountPlugin interface {
	Name() string    // Unique identifier for the plugin
	Version() string // Plugin version in semver format (e.g., "1.0.0")

	// Core account operations
	OnCreate(ctx context.Context, account interface{}) error // Called when an account is created
	OnUpdate(ctx context.Context, account interface{}) error // Called when an account is updated
	OnDelete(ctx context.Context, accountID string) error    // Called when an account is deleted

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize plugin with configuration parameters
	Capabilities() []string                         // Return list of supported capabilities/features
}

// PluginManager provides centralized management for billing plugins.
// Enables hot-swapping and configuration of plugins at runtime.
type PluginManager interface {
	// Plugin registration
	RegisterPlugin(pluginType string, plugin interface{}) error  // Register a new plugin
	UnregisterPlugin(pluginType string, pluginName string) error // Unregister an existing plugin

	// Plugin lookup
	GetInvoicePlugin(name string) (InvoicePlugin, bool)           // Get invoice plugin by name
	GetPaymentPlugin(name string) (PaymentPlugin, bool)           // Get payment plugin by name
	GetTaxPlugin(name string) (TaxPlugin, bool)                   // Get tax plugin by name
	GetSubscriptionPlugin(name string) (SubscriptionPlugin, bool) // Get subscription plugin by name
	GetFeePlugin(name string) (FeePlugin, bool)                   // Get fee plugin by name
	GetAccountPlugin(name string) (AccountPlugin, bool)           // Get account plugin by name
	GetPlugin(pluginType string, name string) (interface{}, bool) // Get any plugin by type and name

	// Plugin listing and lifecycle
	ListPlugins(pluginType string) []string                // List registered plugins by type
	InitializePlugins(config map[string]interface{}) error // Initialize all plugins with configuration
}
