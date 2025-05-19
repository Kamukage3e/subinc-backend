package discount

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type DiscountHandler struct {
	DiscountService DiscountService
	CouponService   CouponService
	CreditService   CreditService
	AccountService  account.ProjectBillingAccountService
	Logger          logger.Logger
}

type PostgresStore struct {
	DB                  *pgxpool.Pool
	AuditLogger         security_management.AuditLogger
	ServerConfigService *server_config.Service
}

type Error struct {
	Code    string
	Message string
	Field   string
	Err     error
}

func NewValidationError(field, msg string) *Error {
	return &Error{
		Code:    "VALIDATION_ERROR",
		Message: msg,
		Field:   field,
	}
}

func (e *Error) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

const (
	CreditTypeAccount    = "account"
	CreditTypeInvoice    = "invoice"
	CreditStatusActive   = "active"
	CreditStatusConsumed = "consumed"
	CreditStatusExpired  = "expired"

	DiscountTypePercentage = "percentage"
	DiscountTypeFixed      = "fixed"
)

// Credit represents a credit applied to an account or invoice
// All fields are required for SaaS billing and auditability
// Type: account, invoice
// Status: active, consumed, expired
// Metadata: JSON-encoded for extensibility
// ID: UUID
// AccountID: required
// InvoiceID: optional
// Amount: must be > 0
// Currency: ISO 4217
// Type: must be account or invoice
// Status: must be active, consumed, or expired
// CreatedAt/UpdatedAt: UTC
// Metadata: JSON string
// OriginalAmount/OriginalCurrency: for FX
// Validate() checks all invariants
type Credit struct {
	ID               string    `json:"id"`
	AccountID        string    `json:"account_id"`
	InvoiceID        string    `json:"invoice_id,omitempty"`
	Amount           float64   `json:"amount"`
	Currency         string    `json:"currency"`
	OriginalAmount   float64   `json:"original_amount,omitempty"`
	OriginalCurrency string    `json:"original_currency,omitempty"`
	Type             string    `json:"type"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Metadata         string    `json:"metadata"`
}

func (c *Credit) Validate() *Error {
	if c.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if c.Amount <= 0 {
		return NewValidationError("amount", "must be greater than zero")
	}
	if c.Currency == "" {
		return NewValidationError("currency", "must not be empty")
	}
	if c.Type != CreditTypeAccount && c.Type != CreditTypeInvoice {
		return NewValidationError("type", "must be 'account' or 'invoice'")
	}
	if c.Status != CreditStatusActive && c.Status != CreditStatusConsumed && c.Status != CreditStatusExpired {
		return NewValidationError("status", "must be 'active', 'consumed', or 'expired'")
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
// ID: UUID
// Code: required, unique
// Type: must be percentage or fixed
// Value: >0, for percentage must be 0-100
// StartAt/EndAt: UTC
// CreatedAt/UpdatedAt: UTC
// Validate() checks all invariants
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

func (d *Discount) Validate() *Error {
	if d.Code == "" {
		return NewValidationError("code", "must not be empty")
	}
	if d.Type != DiscountTypePercentage && d.Type != DiscountTypeFixed {
		return NewValidationError("type", "must be 'percentage' or 'fixed'")
	}
	if d.Value <= 0 {
		return NewValidationError("value", "must be greater than zero")
	}
	if d.Type == DiscountTypePercentage && (d.Value <= 0 || d.Value > 100) {
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
// ID: UUID
// Code: required, unique
// DiscountID: required
// MaxRedemptions: >=0
// Redeemed: >=0
// StartAt/EndAt: UTC
// CreatedAt/UpdatedAt: UTC
// Validate() checks all invariants
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

func (c *Coupon) Validate() *Error {
	if c.Code == "" {
		return NewValidationError("code", "must not be empty")
	}
	if c.DiscountID == "" {
		return NewValidationError("discount_id", "must not be empty")
	}
	if c.MaxRedemptions < 0 {
		return NewValidationError("max_redemptions", "must be non-negative")
	}
	if c.Redeemed < 0 {
		return NewValidationError("redeemed", "must be non-negative")
	}
	return nil
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
