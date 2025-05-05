package domain

import (
	"time"
)

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
