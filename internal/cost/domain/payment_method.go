package domain

import (
	"context"
	"time"
)

// PaymentMethod represents a PCI-compliant payment method for an account
// Only non-sensitive metadata is stored: last4, exp, provider, token, token_provider
// All sensitive card/bank data is tokenized and never stored in the DB
// Token is a reference to the vault/tokenization provider (e.g., Stripe, Adyen, AWS KMS)

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
	Token         string    `json:"token"`          // PCI token reference, never raw PAN
	TokenProvider string    `json:"token_provider"` // e.g., stripe, adyen, aws_kms
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

// TokenizationProvider abstracts PCI-compliant tokenization for payment methods.
// All implementations must be secure, production-grade, and never store sensitive data in the DB.
// Example implementations: Stripe, Adyen, AWS KMS, HashiCorp Vault.
type TokenizationProvider interface {
	// CreateToken securely tokenizes payment data and returns a token reference.
	CreateToken(ctx context.Context, accountID string, paymentData map[string]string) (token string, err error)
	// GetToken retrieves token metadata (never raw PAN or sensitive data).
	GetToken(ctx context.Context, accountID, token string) (metadata map[string]string, err error)
	// DeleteToken removes a token from the vault/provider.
	DeleteToken(ctx context.Context, accountID, token string) error
	// ProviderName returns the name of the tokenization provider (e.g., stripe, adyen, aws_kms).
	ProviderName() string
}
