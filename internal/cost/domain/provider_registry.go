package domain

import (
	"context"
)

// ProviderRegistry defines a registry for cloud provider integrations
// This interface is used to abstract provider lookups for cost import and other operations
// All implementations must be concurrency-safe and production-grade
type ProviderRegistry interface {
	// GetProvider returns a provider implementation for the given cloud provider and credentials
	GetProvider(ctx context.Context, provider CloudProvider, credentials map[string]string) (interface{}, error)
}
