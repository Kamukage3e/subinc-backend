package domain

import (
	"time"
)

// BillingAccount represents a customer billing account
// All fields are required for SaaS billing and auditability
// No sensitive info is stored here
type BillingAccount struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	IsActive  bool      `json:"is_active"`
}

func (a *BillingAccount) Validate() error {
	if a.TenantID == "" || a.Email == "" {
		return ErrInvalidTenant
	}
	return nil
}

// BillingPlan represents a pricing plan (subscription, usage-based, etc.)
type BillingPlan struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// Pricing is a JSON-encoded map for extensibility (tiers, usage, etc.)
	Pricing string `json:"pricing"`
}

func (p *BillingPlan) Validate() error {
	if p.Name == "" || p.Pricing == "" {
		return ErrInvalidPlan
	}
	return nil
}

// UsageEvent represents a single usage record for billing
type UsageEvent struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Resource  string    `json:"resource"`
	Quantity  float64   `json:"quantity"`
	Unit      string    `json:"unit"`
	Timestamp time.Time `json:"timestamp"`
	Metadata  string    `json:"metadata"`
}

func (u *UsageEvent) Validate() error {
	if u.AccountID == "" || u.Resource == "" || u.Quantity < 0 {
		return ErrInvalidUsage
	}
	return nil
}

// Fee represents a fee applied to an invoice or billing item (e.g., service fee, payment processing fee)
type Fee struct {
	Type     string  `json:"type"` // e.g., service, processing, platform
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	Metadata string  `json:"metadata"`
}

// Invoice represents a generated invoice for a billing account
// Now includes tax and fee support for real-world SaaS billing
type Invoice struct {
	ID          string     `json:"id"`
	AccountID   string     `json:"account_id"`
	PeriodStart time.Time  `json:"period_start"`
	PeriodEnd   time.Time  `json:"period_end"`
	Amount      float64    `json:"amount"`
	Currency    string     `json:"currency"`
	Status      string     `json:"status"` // draft, issued, paid, overdue, void
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	PaidAt      *time.Time `json:"paid_at,omitempty"`
	LineItems   string     `json:"line_items"` // JSON-encoded for extensibility
	TaxAmount   float64    `json:"tax_amount"`
	TaxRate     float64    `json:"tax_rate"`
	Fees        string     `json:"fees"` // JSON-encoded []Fee
}

func (i *Invoice) Validate() error {
	if i.AccountID == "" || i.Amount < 0 || i.Currency == "" {
		return ErrInvalidInvoice
	}
	return nil
}

// Payment represents a payment made for an invoice
type Payment struct {
	ID        string    `json:"id"`
	InvoiceID string    `json:"invoice_id"`
	Amount    float64   `json:"amount"`
	Currency  string    `json:"currency"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"` // pending, completed, failed
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Reference string    `json:"reference"`
}

func (p *Payment) Validate() error {
	if p.InvoiceID == "" || p.Amount < 0 || p.Currency == "" {
		return ErrInvalidPayment
	}
	return nil
}

// AuditLog represents an audit event for billing actions
type AuditLog struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
}

func (a *AuditLog) Validate() error {
	if a.ActorID == "" || a.Action == "" || a.TargetID == "" {
		return ErrInvalidAuditLog
	}
	return nil
}
