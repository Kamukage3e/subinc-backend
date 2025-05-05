package cloud

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Errors
var (
	ErrNoTenantInContext  = errors.New("no tenant ID in context")
	ErrNoCredentialsFound = errors.New("no credentials found for tenant")
)

// TenantAwareCostProvider is a CostDataProvider wrapper that handles tenant context
type TenantAwareCostProvider struct {
	registry    *CostDataProviderRegistry
	factory     ProviderFactory
	logger      *logger.Logger
	credentials CredentialStore
}

// CredentialStore is an interface for retrieving cloud provider credentials by tenant
type CredentialStore interface {
	// GetCredentials gets cloud provider credentials for a tenant
	GetCredentials(ctx context.Context, tenantID string, provider domain.CloudProvider) (map[string]string, error)

	// GetDefaultAccountID gets the default account ID for a tenant and provider
	GetDefaultAccountID(ctx context.Context, tenantID string, provider domain.CloudProvider) (string, error)
}

// NewTenantAwareCostProvider creates a new tenant-aware cost provider
func NewTenantAwareCostProvider(
	factory ProviderFactory,
	credentials CredentialStore,
	log *logger.Logger,
) *TenantAwareCostProvider {
	if log == nil {
		log = logger.NewNoop()
	}

	return &TenantAwareCostProvider{
		registry:    NewCostDataProviderRegistry(factory),
		factory:     factory,
		logger:      log,
		credentials: credentials,
	}
}

// getTenantFromContext extracts tenant ID from context
func (p *TenantAwareCostProvider) getTenantFromContext(ctx context.Context) (string, error) {
	// Try to get tenant ID from context
	tenantID, ok := ctx.Value(logger.TenantIDKey).(string)
	if !ok || tenantID == "" {
		// Try any domain.TenantIDKey if defined separately from the logger key
		tenantID, ok = ctx.Value(domain.TenantIDKey).(string)
		if !ok || tenantID == "" {
			return "", ErrNoTenantInContext
		}
	}
	return tenantID, nil
}

// getProviderForTenant gets the appropriate provider for a tenant
func (p *TenantAwareCostProvider) getProviderForTenant(ctx context.Context, cloudProvider domain.CloudProvider) (CostDataProvider, error) {
	// Get tenant ID from context
	tenantID, err := p.getTenantFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Get credentials for the tenant
	credentials, err := p.credentials.GetCredentials(ctx, tenantID, cloudProvider)
	if err != nil {
		p.logger.Error("Failed to get credentials for tenant",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(cloudProvider)),
			logger.ErrorField(err))
		return nil, fmt.Errorf("%w: %v", ErrNoCredentialsFound, err)
	}

	// Get provider from registry
	provider, err := p.registry.GetProvider(ctx, cloudProvider, credentials)
	if err != nil {
		p.logger.Error("Failed to get provider for tenant",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(cloudProvider)),
			logger.ErrorField(err))
		return nil, err
	}

	return provider, nil
}

// FetchCostData retrieves cost data from the appropriate provider for the tenant
func (p *TenantAwareCostProvider) FetchCostData(ctx context.Context, cloudProvider domain.CloudProvider, startTime, endTime time.Time, granularity domain.CostGranularity) ([]*domain.Cost, error) {
	// Get tenant ID from context
	tenantID, err := p.getTenantFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Get provider
	provider, err := p.getProviderForTenant(ctx, cloudProvider)
	if err != nil {
		return nil, err
	}

	// Get default account ID if needed
	accountID, err := p.credentials.GetDefaultAccountID(ctx, tenantID, cloudProvider)
	if err != nil {
		p.logger.Warn("Failed to get default account ID for tenant",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(cloudProvider)),
			logger.ErrorField(err))
		// Continue with empty account ID, which will fetch all accounts
	}

	// Fetch data
	return provider.FetchCostData(ctx, accountID, startTime, endTime, granularity)
}

// ValidateCredentials validates credentials for a tenant
func (p *TenantAwareCostProvider) ValidateCredentials(ctx context.Context, cloudProvider domain.CloudProvider, credentials map[string]string) error {
	// Create a temporary provider to validate
	provider, err := p.factory.CreateProvider(ctx, cloudProvider, credentials)
	if err != nil {
		return err
	}

	// Validate with empty account ID (validates just the credentials)
	return provider.ValidateCredentials(ctx, "", credentials)
}

// FetchCloudAccounts fetches cloud accounts for a tenant
func (p *TenantAwareCostProvider) FetchCloudAccounts(ctx context.Context, cloudProvider domain.CloudProvider) ([]domain.CloudAccount, error) {
	// Get provider
	provider, err := p.getProviderForTenant(ctx, cloudProvider)
	if err != nil {
		return nil, err
	}

	// Get tenant ID from context
	tenantID, err := p.getTenantFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Get credentials for the tenant
	credentials, err := p.credentials.GetCredentials(ctx, tenantID, cloudProvider)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoCredentialsFound, err)
	}

	// Fetch accounts
	return provider.FetchAccounts(ctx, credentials)
}

// HealthCheck performs a health check on all providers
func (p *TenantAwareCostProvider) HealthCheck(ctx context.Context) map[domain.CloudProvider]error {
	results := make(map[domain.CloudProvider]error)

	// Check each provider we support
	for _, providerType := range []domain.CloudProvider{domain.AWS, domain.Azure, domain.GCP} {
		// Try to get a provider - this may fail if we don't have valid credentials
		credentials := map[string]string{} // Minimal credentials that won't fail immediately
		provider, err := p.factory.CreateProvider(ctx, providerType, credentials)

		if err != nil {
			results[providerType] = fmt.Errorf("failed to create provider: %w", err)
			continue
		}

		// Try to check health
		err = provider.HealthCheck(ctx)
		results[providerType] = err
	}

	return results
}
