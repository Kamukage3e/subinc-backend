package domain

import (
	"time"
)

// Discount represents a discount or promo code for billing
// All fields are required for SaaS billing and auditability
// No sensitive info is stored here
// Code must be unique
// Type: percentage or fixed
// Value: percent (0-100) or fixed amount
// MaxRedemptions: 0 = unlimited
// Redeemed: number of times redeemed
// IsActive: whether the discount is currently active
// Metadata: JSON-encoded for extensibility
type Discount struct {
	ID             string    `json:"id"`
	Code           string    `json:"code"`
	Type           string    `json:"type"` // percentage, fixed
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
