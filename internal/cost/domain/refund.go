package domain

import (
	"time"
)

// Refund represents a refund for a payment/invoice
// All fields are required for SaaS billing and auditability
// No sensitive info is stored here
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
