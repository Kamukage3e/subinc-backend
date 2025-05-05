package domain

import (
	"time"
)

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
