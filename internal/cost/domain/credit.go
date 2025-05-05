package domain

import (
	"time"
)

// Credit represents a credit applied to an account or invoice
// All fields are required for SaaS billing and auditability
// No sensitive info is stored here
// Type: account or invoice
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
