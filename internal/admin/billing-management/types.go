package billing_management

import (
	"fmt"
	"time"
)

// Account represents a billing account
// All fields are required for SaaS billing and auditability
// ID is a UUID string
// TenantID is the owning tenant
// Email is the account email
// Status is active, suspended, or closed
// CreatedAt, UpdatedAt are RFC3339 timestamps
type Account struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (a *Account) Validate() error {
	if a.TenantID == "" {
		return NewValidationError("tenant_id", "must not be empty")
	}
	if a.Email == "" {
		return NewValidationError("email", "must not be empty")
	}
	if a.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}

type Plan struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Price       float64   `json:"price"`
	Active      bool      `json:"active"`
	Pricing     string    `json:"pricing"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (p *Plan) Validate() error {
	if p.Name == "" {
		return NewValidationError("name", "must not be empty")
	}
	if p.Price < 0 {
		return NewValidationError("price", "must be non-negative")
	}
	return nil
}

type Usage struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Metric    string    `json:"metric"`
	Amount    float64   `json:"amount"`
	Period    string    `json:"period"`
	CreatedAt time.Time `json:"created_at"`
}

func (u *Usage) Validate() error {
	if u.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if u.Metric == "" {
		return NewValidationError("metric", "must not be empty")
	}
	if u.Amount < 0 {
		return NewValidationError("amount", "must be non-negative")
	}
	return nil
}

type Invoice struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Amount    float64   `json:"amount"`
	Status    string    `json:"status"`
	DueDate   time.Time `json:"due_date"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	TaxAmount float64   `json:"tax_amount"`
	TaxRate   float64   `json:"tax_rate"`
	Fees      string    `json:"fees"`
}

func (i *Invoice) Validate() error {
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

// Payment represents a payment for an invoice
// All fields are required for SaaS billing and auditability
// Status: pending, completed, failed, refunded
// Method: card, bank, etc.
// Metadata: JSON-encoded for extensibility
type Payment struct {
	ID        string    `json:"id"`
	InvoiceID string    `json:"invoice_id"`
	Amount    float64   `json:"amount"`
	Status    string    `json:"status"`
	Method    string    `json:"method"`
	Last4     string    `json:"last4"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Metadata  string    `json:"metadata"`
}

func (p *Payment) Validate() error {
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

// Credit represents a credit applied to an account or invoice
// All fields are required for SaaS billing and auditability
// Type: account, invoice
// Status: active, consumed, expired
// Metadata: JSON-encoded for extensibility
type Credit struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	InvoiceID string    `json:"invoice_id,omitempty"`
	Amount    float64   `json:"amount"`
	Currency  string    `json:"currency"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Metadata  string    `json:"metadata"`
}

func (c *Credit) Validate() error {
	if c.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if c.Amount <= 0 {
		return NewValidationError("amount", "must be greater than zero")
	}
	if c.Currency == "" {
		return NewValidationError("currency", "must not be empty")
	}
	if c.Type != "account" && c.Type != "invoice" {
		return NewValidationError("type", "must be 'account' or 'invoice'")
	}
	if c.Status != "active" && c.Status != "consumed" && c.Status != "expired" {
		return NewValidationError("status", "must be 'active', 'consumed', or 'expired'")
	}
	return nil
}

// Refund represents a refund for a payment/invoice
// All fields are required for SaaS billing and auditability
// Status: pending, processed, failed, reversed
// Metadata: JSON-encoded for extensibility
type Refund struct {
	ID        string    `json:"id"`
	PaymentID string    `json:"payment_id"`
	InvoiceID string    `json:"invoice_id,omitempty"`
	Amount    float64   `json:"amount"`
	Currency  string    `json:"currency"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Metadata  string    `json:"metadata"`
}

func (r *Refund) Validate() error {
	if r.PaymentID == "" {
		return NewValidationError("payment_id", "must not be empty")
	}
	if r.Amount <= 0 {
		return NewValidationError("amount", "must be greater than zero")
	}
	if r.Currency == "" {
		return NewValidationError("currency", "must not be empty")
	}
	if r.Status != "pending" && r.Status != "processed" && r.Status != "failed" && r.Status != "reversed" {
		return NewValidationError("status", "must be 'pending', 'processed', 'failed', or 'reversed'")
	}
	if r.Reason == "" {
		return NewValidationError("reason", "must not be empty")
	}
	return nil
}

// Discount represents a discount or promo code for billing
// All fields are required for SaaS billing and auditability
// Type: percentage, fixed
// Value: percent (0-100) or fixed amount
// MaxRedemptions: 0 = unlimited
// Redeemed: number of times redeemed
// IsActive: whether the discount is currently active
// Metadata: JSON-encoded for extensibility
type Discount struct {
	ID             string    `json:"id"`
	Code           string    `json:"code"`
	Type           string    `json:"type"`
	Value          float64   `json:"value"`
	MaxRedemptions int       `json:"max_redemptions"`
	Redeemed       int       `json:"redeemed"`
	StartAt        time.Time `json:"start_at"`
	EndAt          time.Time `json:"end_at"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Metadata       string    `json:"metadata"`
}

func (d *Discount) Validate() error {
	if d.Code == "" {
		return NewValidationError("code", "must not be empty")
	}
	if d.Type != "percentage" && d.Type != "fixed" {
		return NewValidationError("type", "must be 'percentage' or 'fixed'")
	}
	if d.Value <= 0 {
		return NewValidationError("value", "must be greater than zero")
	}
	if d.Type == "percentage" && (d.Value <= 0 || d.Value > 100) {
		return NewValidationError("value", "must be between 0 and 100 for percentage type")
	}
	if d.StartAt.After(d.EndAt) {
		return NewValidationError("start_at", "must be before end_at")
	}
	return nil
}

// Coupon represents a coupon for a discount
// All fields are required for SaaS billing and auditability
// Metadata: JSON-encoded for extensibility
type Coupon struct {
	ID             string    `json:"id"`
	Code           string    `json:"code"`
	DiscountID     string    `json:"discount_id"`
	MaxRedemptions int       `json:"max_redemptions"`
	Redeemed       int       `json:"redeemed"`
	StartAt        time.Time `json:"start_at"`
	EndAt          time.Time `json:"end_at"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Metadata       string    `json:"metadata"`
}

func (c *Coupon) Validate() error {
	if c.Code == "" {
		return NewValidationError("code", "must not be empty")
	}
	if c.DiscountID == "" {
		return NewValidationError("discount_id", "must not be empty")
	}
	if c.StartAt.After(c.EndAt) {
		return NewValidationError("start_at", "must be before end_at")
	}
	return nil
}

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

func (a *AuditLog) Validate() error {
	if a.ActorID == "" {
		return NewValidationError("actor_id", "must not be empty")
	}
	if a.Action == "" {
		return NewValidationError("action", "must not be empty")
	}
	if a.Hash == "" {
		return NewValidationError("hash", "must not be empty")
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

func (w *WebhookEvent) Validate() error {
	if w.Provider == "" {
		return NewValidationError("provider", "must not be empty")
	}
	if w.EventType == "" {
		return NewValidationError("event_type", "must not be empty")
	}
	if w.Payload == "" {
		return NewValidationError("payload", "must not be empty")
	}
	if w.Status != "received" && w.Status != "processed" && w.Status != "failed" {
		return NewValidationError("status", "must be 'received', 'processed', or 'failed'")
	}
	if w.ReceivedAt.IsZero() {
		return NewValidationError("received_at", "must not be zero")
	}
	return nil
}

// InvoiceAdjustment represents an adjustment (discount/credit/manual) to an invoice
// All fields are required for SaaS billing and auditability
// Type: discount, credit, manual
// Metadata: JSON-encoded for extensibility
type InvoiceAdjustment struct {
	ID        string    `json:"id"`
	InvoiceID string    `json:"invoice_id"`
	Type      string    `json:"type"`
	Amount    float64   `json:"amount"`
	Currency  string    `json:"currency"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Metadata  string    `json:"metadata"`
}

func (a *InvoiceAdjustment) Validate() error {
	if a.InvoiceID == "" {
		return NewValidationError("invoice_id", "must not be empty")
	}
	if a.Type != "discount" && a.Type != "credit" && a.Type != "manual" {
		return NewValidationError("type", "must be 'discount', 'credit', or 'manual'")
	}
	if a.Amount == 0 {
		return NewValidationError("amount", "must not be zero")
	}
	if a.Currency == "" {
		return NewValidationError("currency", "must not be empty")
	}
	if a.Reason == "" {
		return NewValidationError("reason", "must not be empty")
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
// ExpMonth/ExpYear: for cards, 1-12 and >=2000
// Last4: last 4 digits of card/bank
// Provider: payment provider name
// CreatedAt/UpdatedAt: RFC3339 timestamps
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

func (p *PaymentMethod) Validate() error {
	if p.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if p.Type != "card" && p.Type != "bank" && p.Type != "other" {
		return NewValidationError("type", "must be 'card', 'bank', or 'other'")
	}
	if p.Provider == "" {
		return NewValidationError("provider", "must not be empty")
	}
	if len(p.Last4) != 4 {
		return NewValidationError("last4", "must be 4 characters")
	}
	if p.ExpMonth < 1 || p.ExpMonth > 12 {
		return NewValidationError("exp_month", "must be between 1 and 12")
	}
	if p.ExpYear < 2000 {
		return NewValidationError("exp_year", "must be >= 2000")
	}
	if p.Status != "active" && p.Status != "inactive" && p.Status != "expired" && p.Status != "failed" {
		return NewValidationError("status", "must be 'active', 'inactive', 'expired', or 'failed'")
	}
	if p.Token == "" {
		return NewValidationError("token", "must not be empty (PCI token required)")
	}
	if p.TokenProvider == "" {
		return NewValidationError("token_provider", "must not be empty (PCI token provider required)")
	}
	return nil
}

type Subscription struct {
	ID                 string     `json:"id"`
	AccountID          string     `json:"account_id"`
	PlanID             string     `json:"plan_id"`
	Status             string     `json:"status"`
	TrialStart         *time.Time `json:"trial_start,omitempty"`
	TrialEnd           *time.Time `json:"trial_end,omitempty"`
	CurrentPeriodStart time.Time  `json:"current_period_start"`
	CurrentPeriodEnd   time.Time  `json:"current_period_end"`
	CancelAt           *time.Time `json:"cancel_at,omitempty"`
	CanceledAt         *time.Time `json:"canceled_at,omitempty"`
	GracePeriodEnd     *time.Time `json:"grace_period_end,omitempty"`
	DunningUntil       *time.Time `json:"dunning_until,omitempty"`
	ScheduledPlanID    *string    `json:"scheduled_plan_id,omitempty"`
	ScheduledChangeAt  *time.Time `json:"scheduled_change_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	Metadata           string     `json:"metadata"`
}

func (s *Subscription) Validate() error {
	if s.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if s.PlanID == "" {
		return NewValidationError("plan_id", "must not be empty")
	}
	if s.Status != "active" && s.Status != "trialing" && s.Status != "canceled" && s.Status != "grace" && s.Status != "dunning" && s.Status != "past_due" && s.Status != "scheduled" && s.Status != "expired" {
		return NewValidationError("status", "must be a valid subscription status")
	}
	if s.CurrentPeriodStart.IsZero() || s.CurrentPeriodEnd.IsZero() {
		return NewValidationError("current_period", "must not be zero")
	}
	return nil
}

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

func NewValidationError(field, message string) error {
	return &ValidationError{Field: field, Message: message}
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
