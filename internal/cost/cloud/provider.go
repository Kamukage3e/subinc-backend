package cloud

import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/cost/domain"
)

// CostDataProvider defines the interface for retrieving cost data from cloud providers
type CostDataProvider interface {
	// FetchCostData retrieves cost data from the cloud provider
	FetchCostData(ctx context.Context, accountID string, startTime, endTime time.Time, granularity domain.CostGranularity) ([]*domain.Cost, error)

	// GetProviderInfo returns information about the provider
	GetProviderInfo() domain.CloudProviderInfo

	// ValidateCredentials checks if the provided credentials are valid
	ValidateCredentials(ctx context.Context, accountID string, credentials map[string]string) error

	// FetchAccounts retrieves the accounts/subscriptions/projects associated with the provided credentials
	FetchAccounts(ctx context.Context, credentials map[string]string) ([]domain.CloudAccount, error)

	// GetCostCategories returns the supported cost categories for this provider
	GetCostCategories() []domain.CostCategory

	// GetSupportedServices returns the services supported by this provider
	GetSupportedServices() []domain.CloudService

	// GetUsageTypes returns the usage types supported by this provider
	GetUsageTypes() []domain.UsageType

	// FetchResourceUsage retrieves detailed resource usage data
	FetchResourceUsage(ctx context.Context, accountID string, resourceID string, startTime, endTime time.Time) (*domain.ResourceUsage, error)

	// ListBillingItems lists billing line items for an account
	ListBillingItems(ctx context.Context, accountID string, startTime, endTime time.Time, page, pageSize int) ([]*domain.BillingItem, int, error)

	// HealthCheck verifies that the provider API is reachable and working
	HealthCheck(ctx context.Context) error
}

// ProviderFactory creates a cloud provider instance
type ProviderFactory interface {
	// CreateProvider creates a provider instance based on credentials
	CreateProvider(ctx context.Context, provider domain.CloudProvider, credentials map[string]string) (CostDataProvider, error)
}

// CostDataProviderRegistry manages cloud provider implementations
type CostDataProviderRegistry struct {
	providers map[domain.CloudProvider]CostDataProvider
	factory   ProviderFactory
}

// NewCostDataProviderRegistry creates a new registry for cloud providers
func NewCostDataProviderRegistry(factory ProviderFactory) *CostDataProviderRegistry {
	return &CostDataProviderRegistry{
		providers: make(map[domain.CloudProvider]CostDataProvider),
		factory:   factory,
	}
}

// GetProvider returns a provider for the given cloud provider
func (r *CostDataProviderRegistry) GetProvider(ctx context.Context, provider domain.CloudProvider, credentials map[string]string) (CostDataProvider, error) {
	// Check if provider is already initialized
	if p, exists := r.providers[provider]; exists {
		return p, nil
	}

	// Create new provider
	p, err := r.factory.CreateProvider(ctx, provider, credentials)
	if err != nil {
		return nil, err
	}

	// Cache provider
	r.providers[provider] = p
	return p, nil
}

// Adapter for domain.ProviderRegistry
func (r *CostDataProviderRegistry) GetProviderAsInterface(ctx context.Context, provider domain.CloudProvider, credentials map[string]string) (interface{}, error) {
	return r.GetProvider(ctx, provider, credentials)
}

// ResourceInventoryProvider defines resource inventory for a cloud provider
// Real prod interface, no placeholders

type ResourceInventoryProvider interface {
	ListResources(ctx context.Context, accountID string, credentials map[string]string) ([]architecture.ResourceNode, error)
}
