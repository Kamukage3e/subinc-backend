package billing_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	discount "github.com/subinc/subinc-backend/internal/admin/billing-management/discount"
	payment "github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
	tax "github.com/subinc/subinc-backend/internal/admin/billing-management/tax"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// BillingAdminHandler is a struct that contains all the services for the billing admin
type BillingAdminHandler struct {
	InvoiceService             InvoiceService
	WebhookEventService        WebhookEventService
	InvoiceAdjustmentService   InvoiceAdjustmentService
	ManualAdjustmentService    ManualAdjustmentService
	AccountActionService       AccountActionService
	WebhookSubscriptionService WebhookSubscriptionService
	AccountService             account.AccountService
	PaymentMethodService       payment.PaymentMethodService
	CreditService              discount.CreditService
	TaxService                 tax.TaxInfoService
	Store                      *PostgresStore
	PaymentStore               payment.StoreInterface
	AuditLogger                BillingAuditLogger                      // use interface for audit logging
	RateLimitService           security_management.RateLimitService    // for distributed rate limiting
	ConfigService              *server_config.Service                  // for fetching secrets, keys, and static configs from server-config
	Logger                     logger.Logger                           // add logger for webhook and handler logging
	Notify                     security_management.NotificationService // add notification service for webhook and event notifications
}

// Account represents a billing account
// All fields are required for SaaS billing and auditability
// ID is a UUID string
// TenantID is the owning tenant
// Email is the account email
// Status is active, suspended, or closed
// Currency is the ISO 4217 code for the currency
// CreatedAt, UpdatedAt are RFC3339 timestamps

type Invoice struct {
	ID                   string    `json:"id"`
	AccountID            string    `json:"account_id"`
	Amount               float64   `json:"amount"`
	Currency             string    `json:"currency"` // ISO 4217, e.g. USD
	OriginalAmount       float64   `json:"original_amount,omitempty"`
	OriginalCurrency     string    `json:"original_currency,omitempty"`
	Status               string    `json:"status"`
	DueDate              time.Time `json:"due_date"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	TaxAmount            float64   `json:"tax_amount"`
	TaxRate              float64   `json:"tax_rate"`
	Fees                 string    `json:"fees"`
	DunningAttempts      int       `json:"dunning_attempts"`
	DunningNextAttemptAt time.Time `json:"dunning_next_attempt_at"`
	DunningStatus        string    `json:"dunning_status"`
}

func (i *Invoice) Validate() *Error {
	if i.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if i.Amount < 0 {
		return NewValidationError("amount", "must be non-negative")
	}
	if i.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}

// Payment, PaymentMethod, Refund, and related types are now defined in internal/admin/billing-management/payment/types.go

// AuditLog represents an audit log entry for billing actions
// All fields are required for SaaS billing and auditability
// Metadata: JSON-encoded for extensibility
type AuditLog struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	TargetID  string    `json:"target_id"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
	Metadata  string    `json:"metadata"`
	Hash      string    `json:"hash"`
}

func (a *AuditLog) Validate() *Error {
	if a.ActorID == "" {
		return NewValidationError("actor_id", "must not be empty")
	}
	if a.Action == "" {
		return NewValidationError("action", "must not be empty")
	}
	if a.Resource == "" {
		return NewValidationError("resource", "must not be empty")
	}
	if a.TargetID == "" {
		return NewValidationError("target_id", "must not be empty")
	}
	return nil
}

// WebhookEvent represents a webhook event from a payment provider
// All fields are required for SaaS billing and auditability
// Status: received, processed, failed
// Metadata: JSON-encoded for extensibility
type WebhookEvent struct {
	ID          string     `json:"id"`
	Provider    string     `json:"provider"`
	EventType   string     `json:"event_type"`
	Payload     string     `json:"payload"`
	Status      string     `json:"status"`
	ReceivedAt  time.Time  `json:"received_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	Metadata    string     `json:"metadata"`
}

func (w *WebhookEvent) Validate() *Error {
	if w.Provider == "" {
		return NewValidationError("provider", "must not be empty")
	}
	if w.EventType == "" {
		return NewValidationError("event_type", "must not be empty")
	}
	if w.Payload == "" {
		return NewValidationError("payload", "must not be empty")
	}
	return nil
}

// InvoiceAdjustment represents an adjustment (discount/credit/manual) to an invoice
// All fields are required for SaaS billing and auditability
// Type: discount, credit, manual
// Metadata: JSON-encoded for extensibility
type InvoiceAdjustment struct {
	ID               string    `json:"id"`
	InvoiceID        string    `json:"invoice_id"`
	Type             string    `json:"type"`
	Amount           float64   `json:"amount"`
	Currency         string    `json:"currency"`
	OriginalAmount   float64   `json:"original_amount,omitempty"`
	OriginalCurrency string    `json:"original_currency,omitempty"`
	Reason           string    `json:"reason"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Metadata         string    `json:"metadata"`
}

func (a *InvoiceAdjustment) Validate() *Error {
	if a.InvoiceID == "" {
		return NewValidationError("invoice_id", "must not be empty")
	}
	if a.Type == "" {
		return NewValidationError("type", "must not be empty")
	}
	if a.Amount == 0 {
		return NewValidationError("amount", "must not be zero")
	}
	if a.Currency == "" {
		return NewValidationError("currency", "must not be empty")
	}
	return nil
}

// Add tenant-aware fields, API metering, audit, currency, region, localization, webhooks, SLA, rate limiting, plugin types

// APIUsage tracks per-tenant API usage for metering and billing
// All fields are required for SaaS metering and analytics
// Partitioned by tenant_id and api_key for isolation
// Timestamp is RFC3339
// Endpoint is the API route or method
// Count is the number of calls in the period
// Period is ISO8601 (e.g., 2024-06-01T00:00:00Z)
type APIUsage struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	APIKeyID  string    `json:"api_key_id"`
	Endpoint  string    `json:"endpoint"`
	Count     int64     `json:"count"`
	Period    time.Time `json:"period"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKey represents a customer API key/secret for authentication
// All fields are required for SaaS security and auditability
type APIKey struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Key        string     `json:"key"`
	SecretHash string     `json:"secret_hash"`
	Status     string     `json:"status"` // active, revoked, expired
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt time.Time  `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Metadata   string     `json:"metadata"`
}

// APIKeyRotation tracks key rotation events for compliance
type APIKeyRotation struct {
	ID        string    `json:"id"`
	APIKeyID  string    `json:"api_key_id"`
	TenantID  string    `json:"tenant_id"`
	RotatedAt time.Time `json:"rotated_at"`
	ActorID   string    `json:"actor_id"`
}

// RateLimit defines per-tenant or per-key rate limiting for APIs
type RateLimit struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	APIKeyID  string    `json:"api_key_id"`
	Limit     int64     `json:"limit"`
	Period    string    `json:"period"` // e.g., second, minute, hour, day
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SLA defines per-tenant service level agreements
type SLA struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	UptimeTarget float64   `json:"uptime_target"` // e.g., 99.9
	ResponseTime int64     `json:"response_time_ms"`
	SupportLevel string    `json:"support_level"` // e.g., standard, premium
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Plugin represents a customer or third-party add-on/plugin
type Plugin struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"` // webhook, event, transformation, etc.
	Config     string    `json:"config"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// WebhookSubscription for real-time eventing
type WebhookSubscription struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	URL        string    `json:"url"`
	EventTypes []string  `json:"event_types"`
	Secret     string    `json:"secret"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ExchangeRate represents a currency conversion rate (e.g. USD->EUR)
// Used for multi-currency invoice/payment conversion
// Source: e.g. ECB, fixer.io, manual
// UpdatedAt: last update time
// ID: UUID
// BaseCurrency/QuoteCurrency: ISO 4217 codes
// Rate: float64 (1 base = rate quote)
type ExchangeRate struct {
	ID            string    `json:"id"`
	BaseCurrency  string    `json:"base_currency"`  // e.g. USD
	QuoteCurrency string    `json:"quote_currency"` // e.g. EUR
	Rate          float64   `json:"rate"`
	Source        string    `json:"source"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type PostgresStore struct {
	DB                  *pgxpool.Pool
	AuditLogger         security_management.AuditLogger
	ServerConfigService *server_config.Service
}

// TenantCurrency represents the default billing currency for a tenant.
// Used for multi-currency support and invoice/account defaults.
type TenantCurrency struct {
	TenantID  string    `json:"tenant_id"`
	Currency  string    `json:"currency"` // ISO 4217, e.g. USD
	UpdatedAt time.Time `json:"updated_at"`
}

// BillingPermissions defines all permissions related to billing management
// These constants should be used when creating RBAC permissions and roles
const (
	// Resources
	ResourceBilling          = "billing"
	ResourceInvoice          = "billing:invoice"
	ResourcePaymentMethod    = "billing:payment_method"
	ResourceSubscription     = "billing:subscription"
	ResourcePlan             = "billing:plan"
	ResourceDiscount         = "billing:discount"
	ResourceCreditAdjustment = "billing:credit"
	ResourceUsageReport      = "billing:usage_report"
	ResourceTaxSettings      = "billing:tax_settings"

	// Actions
	ActionView          = "view"
	ActionCreate        = "create"
	ActionUpdate        = "update"
	ActionDelete        = "delete"
	ActionCancel        = "cancel"
	ActionResume        = "resume"
	ActionCharge        = "charge"
	ActionRefund        = "refund"
	ActionApply         = "apply"
	ActionExport        = "export"
	ActionApprove       = "approve"
	ActionReject        = "reject"
	ActionAdminOverride = "admin_override"

	// Full permission strings (resource:action)
	PermissionViewBilling   = ResourceBilling + ":" + ActionView
	PermissionManageBilling = ResourceBilling + ":" + ActionUpdate

	PermissionViewInvoices   = ResourceInvoice + ":" + ActionView
	PermissionCreateInvoices = ResourceInvoice + ":" + ActionCreate
	PermissionUpdateInvoices = ResourceInvoice + ":" + ActionUpdate
	PermissionDeleteInvoices = ResourceInvoice + ":" + ActionDelete

	PermissionViewPaymentMethods   = ResourcePaymentMethod + ":" + ActionView
	PermissionCreatePaymentMethods = ResourcePaymentMethod + ":" + ActionCreate
	PermissionUpdatePaymentMethods = ResourcePaymentMethod + ":" + ActionUpdate
	PermissionDeletePaymentMethods = ResourcePaymentMethod + ":" + ActionDelete

	PermissionViewSubscriptions   = ResourceSubscription + ":" + ActionView
	PermissionCreateSubscriptions = ResourceSubscription + ":" + ActionCreate
	PermissionUpdateSubscriptions = ResourceSubscription + ":" + ActionUpdate
	PermissionCancelSubscriptions = ResourceSubscription + ":" + ActionCancel
	PermissionResumeSubscriptions = ResourceSubscription + ":" + ActionResume

	PermissionViewPlans   = ResourcePlan + ":" + ActionView
	PermissionCreatePlans = ResourcePlan + ":" + ActionCreate
	PermissionUpdatePlans = ResourcePlan + ":" + ActionUpdate
	PermissionDeletePlans = ResourcePlan + ":" + ActionDelete

	PermissionViewDiscounts   = ResourceDiscount + ":" + ActionView
	PermissionCreateDiscounts = ResourceDiscount + ":" + ActionCreate
	PermissionUpdateDiscounts = ResourceDiscount + ":" + ActionUpdate
	PermissionDeleteDiscounts = ResourceDiscount + ":" + ActionDelete
	PermissionApplyDiscounts  = ResourceDiscount + ":" + ActionApply

	PermissionViewCreditAdjustments    = ResourceCreditAdjustment + ":" + ActionView
	PermissionCreateCreditAdjustments  = ResourceCreditAdjustment + ":" + ActionCreate
	PermissionApproveCreditAdjustments = ResourceCreditAdjustment + ":" + ActionApprove
	PermissionRejectCreditAdjustments  = ResourceCreditAdjustment + ":" + ActionReject

	PermissionViewUsageReports   = ResourceUsageReport + ":" + ActionView
	PermissionExportUsageReports = ResourceUsageReport + ":" + ActionExport

	PermissionViewTaxSettings   = ResourceTaxSettings + ":" + ActionView
	PermissionUpdateTaxSettings = ResourceTaxSettings + ":" + ActionUpdate
)

// BillingRoles defines predefined roles for billing management
var BillingRoles = map[string][]string{
	"billing_viewer": {
		PermissionViewBilling,
		PermissionViewInvoices,
		PermissionViewPaymentMethods,
		PermissionViewSubscriptions,
		PermissionViewPlans,
		PermissionViewDiscounts,
		PermissionViewCreditAdjustments,
		PermissionViewUsageReports,
		PermissionViewTaxSettings,
	},
	"billing_manager": {
		PermissionViewBilling,
		PermissionManageBilling,
		PermissionViewInvoices,
		PermissionCreateInvoices,
		PermissionUpdateInvoices,
		PermissionViewPaymentMethods,
		PermissionCreatePaymentMethods,
		PermissionUpdatePaymentMethods,
		PermissionDeletePaymentMethods,
		PermissionViewSubscriptions,
		PermissionUpdateSubscriptions,
		PermissionCancelSubscriptions,
		PermissionResumeSubscriptions,
		PermissionViewPlans,
		PermissionViewDiscounts,
		PermissionApplyDiscounts,
		PermissionViewCreditAdjustments,
		PermissionCreateCreditAdjustments,
		PermissionViewUsageReports,
		PermissionExportUsageReports,
		PermissionViewTaxSettings,
		PermissionUpdateTaxSettings,
	},
	"billing_admin": {
		PermissionViewBilling,
		PermissionManageBilling,
		PermissionViewInvoices,
		PermissionCreateInvoices,
		PermissionUpdateInvoices,
		PermissionDeleteInvoices,
		PermissionViewPaymentMethods,
		PermissionCreatePaymentMethods,
		PermissionUpdatePaymentMethods,
		PermissionDeletePaymentMethods,
		PermissionViewSubscriptions,
		PermissionCreateSubscriptions,
		PermissionUpdateSubscriptions,
		PermissionCancelSubscriptions,
		PermissionResumeSubscriptions,
		PermissionViewPlans,
		PermissionCreatePlans,
		PermissionUpdatePlans,
		PermissionDeletePlans,
		PermissionViewDiscounts,
		PermissionCreateDiscounts,
		PermissionUpdateDiscounts,
		PermissionDeleteDiscounts,
		PermissionApplyDiscounts,
		PermissionViewCreditAdjustments,
		PermissionCreateCreditAdjustments,
		PermissionApproveCreditAdjustments,
		PermissionRejectCreditAdjustments,
		PermissionViewUsageReports,
		PermissionExportUsageReports,
		PermissionViewTaxSettings,
		PermissionUpdateTaxSettings,
	},
}
