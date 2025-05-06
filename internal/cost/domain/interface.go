package domain

import (
	"context"
)

// OptimizationEngine defines the interface for all optimization providers
// (OpenAI, AWS, Azure, GCP, etc.)
type OptimizationEngine interface {
	GenerateRecommendations(req *OptimizationRequest) ([]*OptimizationRecommendation, error)
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

// ProviderRegistry defines a registry for cloud provider integrations
// This interface is used to abstract provider lookups for cost import and other operations
// All implementations must be concurrency-safe and production-grade
type ProviderRegistry interface {
	// GetProvider returns a provider implementation for the given cloud provider and credentials
	GetProvider(ctx context.Context, provider CloudProvider, credentials map[string]string) (interface{}, error)
}
