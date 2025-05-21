package billing_management

import (
	"fmt"
	"reflect"
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
	AccountService             account.BillingAccountService
	AccountHandler             *account.AccountHandler
	PaymentMethodService       payment.PaymentMethodService
	CreditService              discount.CreditService
	TaxService                 tax.TaxInfoService
	ReportService              ReportService
	DunningService             DunningService
	InvoiceExportService       InvoiceExportService
	Store                      *PostgresStore
	PaymentStore               payment.StoreInterface
	AuditLogger                BillingAuditLogger                      // use interface for audit logging
	RateLimitService           security_management.RateLimitService    // for distributed rate limiting
	ConfigService              *server_config.Service                  // for fetching secrets, keys, and static configs from server-config
	Logger                     *logger.Logger                          // add logger for webhook and handler logging
	Notify                     security_management.NotificationService // add notification service for webhook and event notifications
	PluginManager              PluginManager                           // for managing hot-pluggable billing plugins
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
	PluginName           string    `json:"plugin_name"`
	DunningAttempts      int       `json:"dunning_attempts"`
	DunningNextAttemptAt time.Time `json:"dunning_next_attempt_at"`
	DunningStatus        string    `json:"dunning_status"`
}

// DunningEvent represents an event in the dunning process
type DunningEvent struct {
	ID        string                 `json:"id"`
	AccountID string                 `json:"account_id"`
	InvoiceID string                 `json:"invoice_id"`
	EventType string                 `json:"event_type"` // payment_failed, retry, success, canceled, etc.
	Status    string                 `json:"status"`     // pending, processed, failed
	Details   map[string]interface{} `json:"details"`    // Additional context specific to the event
	CreatedAt time.Time              `json:"created_at"`
}

// DunningDashboard contains dunning metrics and statistics
type DunningDashboard struct {
	TenantID             string         `json:"tenant_id"`
	ActiveCount          int            `json:"active_count"`
	CompletedCount       int            `json:"completed_count"`
	FailedCount          int            `json:"failed_count"`
	PausedCount          int            `json:"paused_count"`
	TotalAmountInDunning float64        `json:"total_amount_in_dunning"`
	SuccessRate          float64        `json:"success_rate"`
	RecentEvents         []DunningEvent `json:"recent_events"`
	GeneratedAt          time.Time      `json:"generated_at"`
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

// WebhookDeliveryLog tracks webhook delivery attempts and responses
type WebhookDeliveryLog struct {
	ID                string     `json:"id"`
	WebhookID         string     `json:"webhook_id"`
	EventType         string     `json:"event_type"`
	URL               string     `json:"url"`
	RequestHeaders    string     `json:"request_headers"`
	RequestBody       string     `json:"request_body"`
	ResponseStatus    int        `json:"response_status"`
	ResponseHeaders   string     `json:"response_headers"`
	ResponseBody      string     `json:"response_body"`
	DeliveryAttempts  int        `json:"delivery_attempts"`
	Success           bool       `json:"success"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	DeliveredAt       *time.Time `json:"delivered_at,omitempty"`
	NextRetryAt       *time.Time `json:"next_retry_at,omitempty"`
	LastRetryFailedAt *time.Time `json:"last_retry_failed_at,omitempty"`
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
	DB *pgxpool.Pool

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

// InvoicePluginRegistry holds registered plugins by name.
type InvoicePluginRegistry struct {
	plugins map[string]InvoicePlugin
}

func (r *InvoicePluginRegistry) Register(name string, plugin InvoicePlugin) {
	if r.plugins == nil {
		r.plugins = make(map[string]InvoicePlugin)
	}
	r.plugins[name] = plugin
}

func (r *InvoicePluginRegistry) Lookup(name string) (InvoicePlugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

// InvoicePluginConfig stores per-tenant plugin selection.
type InvoicePluginConfig struct {
	TenantID   string    `json:"tenant_id"`
	PluginName string    `json:"plugin_name"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Address represents a billing address for tax calculation
// All fields are required for tax compliance
type Address struct {
	ID         string `json:"id"`
	Line1      string `json:"line1"`
	Line2      string `json:"line2,omitempty"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"` // ISO 3166-1 alpha-2
	Validated  bool   `json:"validated"`
}

// TaxLine represents a single tax applied to an invoice
// All fields are required for tax compliance
type TaxLine struct {
	ID           string  `json:"id"`
	InvoiceID    string  `json:"invoice_id"`
	TaxType      string  `json:"tax_type"` // e.g., VAT, GST, Sales Tax
	TaxRate      float64 `json:"tax_rate"`
	TaxAmount    float64 `json:"tax_amount"`
	Jurisdiction string  `json:"jurisdiction"`
	TaxID        string  `json:"tax_id,omitempty"` // e.g., VAT number
	Exempt       bool    `json:"exempt"`
	Reason       string  `json:"reason,omitempty"` // reason for exemption
}

// DefaultPluginManager implements the PluginManager interface.
type DefaultPluginManager struct {
	invoicePlugins      map[string]InvoicePlugin
	paymentPlugins      map[string]PaymentPlugin
	taxPlugins          map[string]TaxPlugin
	subscriptionPlugins map[string]SubscriptionPlugin
	feePlugins          map[string]FeePlugin
	accountPlugins      map[string]AccountPlugin
	logger              *logger.Logger
}

// NewPluginManager creates a new DefaultPluginManager
func NewPluginManager(logger *logger.Logger) *DefaultPluginManager {
	// Use the provided logger or keep it nil - the service that uses the plugin manager
	// should always provide a logger, so we don't create one here to avoid package cycles
	return &DefaultPluginManager{
		invoicePlugins:      make(map[string]InvoicePlugin),
		paymentPlugins:      make(map[string]PaymentPlugin),
		taxPlugins:          make(map[string]TaxPlugin),
		subscriptionPlugins: make(map[string]SubscriptionPlugin),
		feePlugins:          make(map[string]FeePlugin),
		accountPlugins:      make(map[string]AccountPlugin),
		logger:              logger,
	}
}

// RegisterPlugin registers a plugin of a specific type
func (pm *DefaultPluginManager) RegisterPlugin(pluginType string, plugin interface{}) error {
	if pluginType == "" {
		return fmt.Errorf("plugin type cannot be empty")
	}

	if plugin == nil {
		return fmt.Errorf("plugin cannot be nil")
	}

	// Use reflection to get the plugin's Name() method
	pluginValue := reflect.ValueOf(plugin)
	nameMethod := pluginValue.MethodByName("Name")
	if !nameMethod.IsValid() {
		return fmt.Errorf("plugin must have a Name() method")
	}

	nameResult := nameMethod.Call([]reflect.Value{})
	if len(nameResult) == 0 {
		return fmt.Errorf("plugin Name() method did not return a result")
	}

	name := nameResult[0].String()
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	var version string
	if versionMethod := pluginValue.MethodByName("Version"); versionMethod.IsValid() {
		versionResult := versionMethod.Call([]reflect.Value{})
		if len(versionResult) > 0 {
			version = versionResult[0].String()
		}
	}

	switch pluginType {
	case "invoice":
		invoicePlugin, ok := plugin.(InvoicePlugin)
		if !ok {
			return fmt.Errorf("plugin is not an InvoicePlugin")
		}

		if _, exists := pm.invoicePlugins[name]; exists {
			return fmt.Errorf("invoice plugin %s is already registered", name)
		}

		pm.invoicePlugins[name] = invoicePlugin

	case "payment":
		paymentPlugin, ok := plugin.(PaymentPlugin)
		if !ok {
			return fmt.Errorf("plugin is not a PaymentPlugin")
		}

		if _, exists := pm.paymentPlugins[name]; exists {
			return fmt.Errorf("payment plugin %s is already registered", name)
		}

		pm.paymentPlugins[name] = paymentPlugin

	case "tax":
		taxPlugin, ok := plugin.(TaxPlugin)
		if !ok {
			return fmt.Errorf("plugin is not a TaxPlugin")
		}

		if _, exists := pm.taxPlugins[name]; exists {
			return fmt.Errorf("tax plugin %s is already registered", name)
		}

		pm.taxPlugins[name] = taxPlugin

	case "subscription":
		subscriptionPlugin, ok := plugin.(SubscriptionPlugin)
		if !ok {
			return fmt.Errorf("plugin is not a SubscriptionPlugin")
		}

		if _, exists := pm.subscriptionPlugins[name]; exists {
			return fmt.Errorf("subscription plugin %s is already registered", name)
		}

		pm.subscriptionPlugins[name] = subscriptionPlugin

	case "fee":
		feePlugin, ok := plugin.(FeePlugin)
		if !ok {
			return fmt.Errorf("plugin is not a FeePlugin")
		}

		if _, exists := pm.feePlugins[name]; exists {
			return fmt.Errorf("fee plugin %s is already registered", name)
		}

		pm.feePlugins[name] = feePlugin

	case "account":
		accountPlugin, ok := plugin.(AccountPlugin)
		if !ok {
			return fmt.Errorf("plugin is not an AccountPlugin")
		}

		if _, exists := pm.accountPlugins[name]; exists {
			return fmt.Errorf("account plugin %s is already registered", name)
		}

		pm.accountPlugins[name] = accountPlugin

	default:
		return fmt.Errorf("unsupported plugin type: %s", pluginType)
	}

	pm.logger.Info(fmt.Sprintf("Registered %s plugin: %s (%s)", pluginType, name, version))
	return nil
}

// UnregisterPlugin unregisters a plugin of a specific type
func (pm *DefaultPluginManager) UnregisterPlugin(pluginType string, pluginName string) error {
	if pluginType == "" {
		return fmt.Errorf("plugin type cannot be empty")
	}

	if pluginName == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	var exists bool

	switch pluginType {
	case "invoice":
		_, exists = pm.invoicePlugins[pluginName]
		if !exists {
			return fmt.Errorf("invoice plugin %s is not registered", pluginName)
		}
		delete(pm.invoicePlugins, pluginName)

	case "payment":
		_, exists = pm.paymentPlugins[pluginName]
		if !exists {
			return fmt.Errorf("payment plugin %s is not registered", pluginName)
		}
		delete(pm.paymentPlugins, pluginName)

	case "tax":
		_, exists = pm.taxPlugins[pluginName]
		if !exists {
			return fmt.Errorf("tax plugin %s is not registered", pluginName)
		}
		delete(pm.taxPlugins, pluginName)

	case "subscription":
		_, exists = pm.subscriptionPlugins[pluginName]
		if !exists {
			return fmt.Errorf("subscription plugin %s is not registered", pluginName)
		}
		delete(pm.subscriptionPlugins, pluginName)

	case "fee":
		_, exists = pm.feePlugins[pluginName]
		if !exists {
			return fmt.Errorf("fee plugin %s is not registered", pluginName)
		}
		delete(pm.feePlugins, pluginName)

	case "account":
		_, exists = pm.accountPlugins[pluginName]
		if !exists {
			return fmt.Errorf("account plugin %s is not registered", pluginName)
		}
		delete(pm.accountPlugins, pluginName)

	default:
		return fmt.Errorf("unsupported plugin type: %s", pluginType)
	}

	pm.logger.Info(fmt.Sprintf("Unregistered %s plugin: %s", pluginType, pluginName))
	return nil
}

// GetInvoicePlugin returns an invoice plugin by name
func (pm *DefaultPluginManager) GetInvoicePlugin(name string) (InvoicePlugin, bool) {
	plugin, exists := pm.invoicePlugins[name]
	return plugin, exists
}

// GetPaymentPlugin returns a payment plugin by name
func (pm *DefaultPluginManager) GetPaymentPlugin(name string) (PaymentPlugin, bool) {
	plugin, exists := pm.paymentPlugins[name]
	return plugin, exists
}

// GetTaxPlugin returns a tax plugin by name
func (pm *DefaultPluginManager) GetTaxPlugin(name string) (TaxPlugin, bool) {
	plugin, exists := pm.taxPlugins[name]
	return plugin, exists
}

// ListPlugins returns a list of registered plugins by type
func (pm *DefaultPluginManager) ListPlugins(pluginType string) []string {
	if pluginType == "" {
		return []string{}
	}

	var pluginNames []string

	switch pluginType {
	case "invoice":
		pluginNames = make([]string, 0, len(pm.invoicePlugins))
		for name := range pm.invoicePlugins {
			pluginNames = append(pluginNames, name)
		}
	case "payment":
		pluginNames = make([]string, 0, len(pm.paymentPlugins))
		for name := range pm.paymentPlugins {
			pluginNames = append(pluginNames, name)
		}
	case "tax":
		pluginNames = make([]string, 0, len(pm.taxPlugins))
		for name := range pm.taxPlugins {
			pluginNames = append(pluginNames, name)
		}
	case "subscription":
		pluginNames = make([]string, 0, len(pm.subscriptionPlugins))
		for name := range pm.subscriptionPlugins {
			pluginNames = append(pluginNames, name)
		}
	case "fee":
		pluginNames = make([]string, 0, len(pm.feePlugins))
		for name := range pm.feePlugins {
			pluginNames = append(pluginNames, name)
		}
	case "account":
		pluginNames = make([]string, 0, len(pm.accountPlugins))
		for name := range pm.accountPlugins {
			pluginNames = append(pluginNames, name)
		}
	}

	return pluginNames
}

// InitializePlugins initializes all registered plugins with provided configuration
func (pm *DefaultPluginManager) InitializePlugins(config map[string]interface{}) error {
	if config == nil {
		return fmt.Errorf("plugin configuration cannot be nil")
	}

	// Initialize invoice plugins
	for name, plugin := range pm.invoicePlugins {
		if err := plugin.Initialize(config); err != nil {
			pm.logger.Error(fmt.Sprintf("Failed to initialize invoice plugin %s: %v", name, err))
			return fmt.Errorf("failed to initialize invoice plugin %s: %w", name, err)
		}
		pm.logger.Info(fmt.Sprintf("Initialized invoice plugin: %s", name))
	}

	// Initialize payment plugins
	for name, plugin := range pm.paymentPlugins {
		if err := plugin.Initialize(config); err != nil {
			pm.logger.Error(fmt.Sprintf("Failed to initialize payment plugin %s: %v", name, err))
			return fmt.Errorf("failed to initialize payment plugin %s: %w", name, err)
		}
		pm.logger.Info(fmt.Sprintf("Initialized payment plugin: %s", name))
	}

	// Initialize tax plugins
	for name, plugin := range pm.taxPlugins {
		if err := plugin.Initialize(config); err != nil {
			pm.logger.Error(fmt.Sprintf("Failed to initialize tax plugin %s: %v", name, err))
			return fmt.Errorf("failed to initialize tax plugin %s: %w", name, err)
		}
		pm.logger.Info(fmt.Sprintf("Initialized tax plugin: %s", name))
	}

	// Initialize subscription plugins
	for name, plugin := range pm.subscriptionPlugins {
		if err := plugin.Initialize(config); err != nil {
			pm.logger.Error(fmt.Sprintf("Failed to initialize subscription plugin %s: %v", name, err))
			return fmt.Errorf("failed to initialize subscription plugin %s: %w", name, err)
		}
		pm.logger.Info(fmt.Sprintf("Initialized subscription plugin: %s", name))
	}

	// Initialize fee plugins
	for name, plugin := range pm.feePlugins {
		if err := plugin.Initialize(config); err != nil {
			pm.logger.Error(fmt.Sprintf("Failed to initialize fee plugin %s: %v", name, err))
			return fmt.Errorf("failed to initialize fee plugin %s: %w", name, err)
		}
		pm.logger.Info(fmt.Sprintf("Initialized fee plugin: %s", name))
	}

	// Initialize account plugins
	for name, plugin := range pm.accountPlugins {
		if err := plugin.Initialize(config); err != nil {
			pm.logger.Error(fmt.Sprintf("Failed to initialize account plugin %s: %v", name, err))
			return fmt.Errorf("failed to initialize account plugin %s: %w", name, err)
		}
		pm.logger.Info(fmt.Sprintf("Initialized account plugin: %s", name))
	}

	return nil
}

// GetPlugin returns a plugin by type and name
func (pm *DefaultPluginManager) GetPlugin(pluginType string, name string) (interface{}, bool) {
	switch pluginType {
	case "invoice":
		plugin, exists := pm.GetInvoicePlugin(name)
		return plugin, exists
	case "payment":
		plugin, exists := pm.GetPaymentPlugin(name)
		return plugin, exists
	case "tax":
		plugin, exists := pm.GetTaxPlugin(name)
		return plugin, exists
	case "subscription":
		plugin, exists := pm.GetSubscriptionPlugin(name)
		return plugin, exists
	case "fee":
		plugin, exists := pm.GetFeePlugin(name)
		return plugin, exists
	case "account":
		plugin, exists := pm.GetAccountPlugin(name)
		return plugin, exists
	default:
		return nil, false
	}
}

// GetSubscriptionPlugin returns a subscription plugin by name
func (pm *DefaultPluginManager) GetSubscriptionPlugin(name string) (SubscriptionPlugin, bool) {
	plugin, exists := pm.subscriptionPlugins[name]
	return plugin, exists
}

// GetFeePlugin returns a fee plugin by name
func (pm *DefaultPluginManager) GetFeePlugin(name string) (FeePlugin, bool) {
	plugin, exists := pm.feePlugins[name]
	return plugin, exists
}

// GetAccountPlugin returns an account plugin by name
func (pm *DefaultPluginManager) GetAccountPlugin(name string) (AccountPlugin, bool) {
	plugin, exists := pm.accountPlugins[name]
	return plugin, exists
}
