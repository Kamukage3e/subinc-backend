package billing

import (
	"context"
	"time"
)

// Invoice represents a billing invoice for a tenant/org.
type Invoice struct {
	ID        string     `json:"id" db:"id"`
	TenantID  string     `json:"tenant_id" db:"tenant_id"`
	OrgID     string     `json:"org_id" db:"org_id"`
	Amount    float64    `json:"amount" db:"amount"`
	Currency  string     `json:"currency" db:"currency"`
	Period    string     `json:"period" db:"period"` // monthly, quarterly, yearly
	Status    string     `json:"status" db:"status"`
	IssuedAt  time.Time  `json:"issued_at" db:"issued_at"`
	DueAt     time.Time  `json:"due_at" db:"due_at"`
	PaidAt    *time.Time `json:"paid_at" db:"paid_at"`
	LineItems []LineItem `json:"line_items" db:"-"`
}

// LineItem represents a line item on an invoice.
type LineItem struct {
	Description string  `json:"description" db:"description"`
	Amount      float64 `json:"amount" db:"amount"`
	Quantity    int     `json:"quantity" db:"quantity"`
}

// CostCenter represents a cost center for billing allocation.
type CostCenter struct {
	ID        string    `json:"id" db:"id"`
	OrgID     string    `json:"org_id" db:"org_id"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// BillingStore defines storage for invoices and cost centers.
type BillingStore interface {
	CreateInvoice(ctx context.Context, inv *Invoice) error
	GetInvoice(ctx context.Context, id string) (*Invoice, error)
	ListInvoices(ctx context.Context, tenantID, orgID string, period string, status string, limit, offset int) ([]*Invoice, error)
	MarkInvoicePaid(ctx context.Context, id string, paidAt time.Time) error

	CreateCostCenter(ctx context.Context, cc *CostCenter) error
	GetCostCenter(ctx context.Context, id string) (*CostCenter, error)
	ListCostCenters(ctx context.Context, orgID string) ([]*CostCenter, error)
	UpdateCostCenter(ctx context.Context, cc *CostCenter) error
	DeleteCostCenter(ctx context.Context, id string) error
}
