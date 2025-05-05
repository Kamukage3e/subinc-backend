package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/cost/cloud"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Errors
var (
	ErrInvalidCloudProvider = errors.New("invalid cloud provider")
	ErrIntegrationNotFound  = errors.New("cloud integration not found")
	ErrDuplicateIntegration = errors.New("cloud integration with this name already exists")
)

// CloudProviderService manages cloud provider integrations
type CloudProviderService interface {
	// AddCloudIntegration adds a new cloud provider integration
	AddCloudIntegration(ctx context.Context, tenantID string, provider domain.CloudProvider, name string, credentials map[string]string) (*repository.CloudCredential, error)

	// UpdateCloudIntegration updates an existing cloud provider integration
	UpdateCloudIntegration(ctx context.Context, tenantID string, integrationID string, credentials map[string]string) (*repository.CloudCredential, error)

	// DeleteCloudIntegration deletes a cloud provider integration
	DeleteCloudIntegration(ctx context.Context, tenantID string, integrationID string) error

	// GetCloudIntegration gets a cloud provider integration by ID
	GetCloudIntegration(ctx context.Context, tenantID string, integrationID string) (*repository.CloudCredential, error)

	// ListCloudIntegrations lists all cloud provider integrations for a tenant
	ListCloudIntegrations(ctx context.Context, tenantID string, providerFilter *domain.CloudProvider) ([]*repository.CloudCredential, error)

	// ValidateCloudIntegration validates a cloud provider integration
	ValidateCloudIntegration(ctx context.Context, tenantID string, integrationID string) (*repository.CloudCredential, error)

	// ListCloudAccounts lists cloud accounts/subscriptions/projects for a tenant's integration
	ListCloudAccounts(ctx context.Context, tenantID string, integrationID string) ([]domain.CloudAccount, error)

	// GetProviderInfo gets information about a cloud provider
	GetProviderInfo(ctx context.Context, provider domain.CloudProvider) (*domain.CloudProviderInfo, error)

	// GetSupportedProviders gets a list of supported cloud providers
	GetSupportedProviders(ctx context.Context) []domain.CloudProvider

	// ImportCostData initiates a cost data import from a cloud provider
	ImportCostData(ctx context.Context, tenantID string, provider domain.CloudProvider, startDate, endDate time.Time) (*domain.CostImport, error)
}

// cloudProviderService implements CloudProviderService
type cloudProviderService struct {
	credentialRepo   *repository.CredentialRepository
	providerFactory  cloud.ProviderFactory
	tenantProvider   *cloud.TenantAwareCostProvider
	costService      CostService
	logger           *logger.Logger
	importsBatchSize int
}

// NewCloudProviderService creates a new cloud provider service
func NewCloudProviderService(
	credentialRepo *repository.CredentialRepository,
	providerFactory cloud.ProviderFactory,
	costService CostService,
	log *logger.Logger,
) CloudProviderService {
	if log == nil {
		log = logger.NewNoop()
	}

	tenantProvider := cloud.NewTenantAwareCostProvider(
		providerFactory,
		credentialRepo,
		log,
	)

	return &cloudProviderService{
		credentialRepo:   credentialRepo,
		providerFactory:  providerFactory,
		tenantProvider:   tenantProvider,
		costService:      costService,
		logger:           log,
		importsBatchSize: 1000, // Default batch size
	}
}

// AddCloudIntegration adds a new cloud provider integration
func (s *cloudProviderService) AddCloudIntegration(
	ctx context.Context,
	tenantID string,
	provider domain.CloudProvider,
	name string,
	credentials map[string]string,
) (*repository.CloudCredential, error) {
	// Validate provider
	if !isValidProvider(provider) {
		return nil, ErrInvalidCloudProvider
	}

	// Validate the credentials
	tempProvider, err := s.providerFactory.CreateProvider(ctx, provider, credentials)
	if err != nil {
		s.logger.Error("Failed to create provider for validation",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(provider)),
			logger.ErrorField(err))
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// Validate credentials (with empty account ID)
	if err := tempProvider.ValidateCredentials(ctx, "", credentials); err != nil {
		s.logger.Error("Credential validation failed",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(provider)),
			logger.ErrorField(err))
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// Create the credential object
	now := time.Now().UTC()
	credential := &repository.CloudCredential{
		ID:              uuid.New().String(),
		TenantID:        tenantID,
		Provider:        provider,
		Name:            name,
		Credentials:     credentials,
		CreatedAt:       now,
		UpdatedAt:       now,
		LastValidatedAt: &now,
		IsValid:         true,
	}

	// Save the credentials
	if err := s.credentialRepo.CreateCredential(ctx, credential); err != nil {
		if errors.Is(err, repository.ErrCredentialExists) {
			return nil, ErrDuplicateIntegration
		}
		s.logger.Error("Failed to create credential",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(provider)),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}

	// Try to fetch and save accounts
	s.fetchAndSaveAccounts(ctx, credential)

	return credential, nil
}

// UpdateCloudIntegration updates an existing cloud provider integration
func (s *cloudProviderService) UpdateCloudIntegration(
	ctx context.Context,
	tenantID string,
	integrationID string,
	credentials map[string]string,
) (*repository.CloudCredential, error) {
	// Get the existing credential
	credential, err := s.credentialRepo.GetCredential(ctx, integrationID)
	if err != nil {
		if errors.Is(err, repository.ErrCredentialNotFound) {
			return nil, ErrIntegrationNotFound
		}
		return nil, err
	}

	// Verify tenant ownership
	if credential.TenantID != tenantID {
		return nil, repository.ErrPermissionDenied
	}

	// Validate the new credentials
	tempProvider, err := s.providerFactory.CreateProvider(ctx, credential.Provider, credentials)
	if err != nil {
		s.logger.Error("Failed to create provider for validation",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(credential.Provider)),
			logger.ErrorField(err))
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// Validate credentials (with empty account ID)
	if err := tempProvider.ValidateCredentials(ctx, "", credentials); err != nil {
		s.logger.Error("Credential validation failed",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(credential.Provider)),
			logger.ErrorField(err))
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// Update the credential
	now := time.Now().UTC()
	credential.Credentials = credentials
	credential.UpdatedAt = now
	credential.LastValidatedAt = &now
	credential.IsValid = true

	// Save the credentials
	if err := s.credentialRepo.UpdateCredential(ctx, credential); err != nil {
		s.logger.Error("Failed to update credential",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to update credentials: %w", err)
	}

	// Try to fetch and save accounts
	s.fetchAndSaveAccounts(ctx, credential)

	return credential, nil
}

// DeleteCloudIntegration deletes a cloud provider integration
func (s *cloudProviderService) DeleteCloudIntegration(
	ctx context.Context,
	tenantID string,
	integrationID string,
) error {
	// Attempt to delete
	err := s.credentialRepo.DeleteCredential(ctx, integrationID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrCredentialNotFound) {
			return ErrIntegrationNotFound
		}
		s.logger.Error("Failed to delete credential",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return fmt.Errorf("failed to delete cloud integration: %w", err)
	}

	return nil
}

// GetCloudIntegration gets a cloud provider integration by ID
func (s *cloudProviderService) GetCloudIntegration(
	ctx context.Context,
	tenantID string,
	integrationID string,
) (*repository.CloudCredential, error) {
	// Get the credential
	credential, err := s.credentialRepo.GetCredential(ctx, integrationID)
	if err != nil {
		if errors.Is(err, repository.ErrCredentialNotFound) {
			return nil, ErrIntegrationNotFound
		}
		return nil, err
	}

	// Verify tenant ownership
	if credential.TenantID != tenantID {
		return nil, repository.ErrPermissionDenied
	}

	return credential, nil
}

// ListCloudIntegrations lists all cloud provider integrations for a tenant
func (s *cloudProviderService) ListCloudIntegrations(
	ctx context.Context,
	tenantID string,
	providerFilter *domain.CloudProvider,
) ([]*repository.CloudCredential, error) {
	var credentials []*repository.CloudCredential
	var err error

	if providerFilter != nil {
		// Get credentials for specific provider
		credentials, err = s.credentialRepo.GetCredentialsByProvider(ctx, tenantID, *providerFilter)
	} else {
		// Get all credentials for tenant
		credentials, err = s.credentialRepo.GetCredentialsByTenant(ctx, tenantID)
	}

	if err != nil {
		s.logger.Error("Failed to list credentials",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to list cloud integrations: %w", err)
	}

	return credentials, nil
}

// ValidateCloudIntegration validates a cloud provider integration
func (s *cloudProviderService) ValidateCloudIntegration(
	ctx context.Context,
	tenantID string,
	integrationID string,
) (*repository.CloudCredential, error) {
	// Get the credential
	credential, err := s.credentialRepo.GetCredential(ctx, integrationID)
	if err != nil {
		if errors.Is(err, repository.ErrCredentialNotFound) {
			return nil, ErrIntegrationNotFound
		}
		return nil, err
	}

	// Verify tenant ownership
	if credential.TenantID != tenantID {
		return nil, repository.ErrPermissionDenied
	}

	// Create a provider to validate
	tempProvider, err := s.providerFactory.CreateProvider(ctx, credential.Provider, credential.Credentials)
	if err != nil {
		s.logger.Error("Failed to create provider for validation",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to validate: %w", err)
	}

	// Validate the credential
	if err := s.credentialRepo.ValidateCredential(ctx, integrationID, tenantID, tempProvider); err != nil {
		s.logger.Error("Credential validation failed",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Reload after validation
	credential, err = s.credentialRepo.GetCredential(ctx, integrationID)
	if err != nil {
		return nil, err
	}

	return credential, nil
}

// ListCloudAccounts lists cloud accounts/subscriptions/projects for a tenant's integration
func (s *cloudProviderService) ListCloudAccounts(
	ctx context.Context,
	tenantID string,
	integrationID string,
) ([]domain.CloudAccount, error) {
	// Get the credential
	credential, err := s.credentialRepo.GetCredential(ctx, integrationID)
	if err != nil {
		if errors.Is(err, repository.ErrCredentialNotFound) {
			return nil, ErrIntegrationNotFound
		}
		return nil, err
	}

	// Verify tenant ownership
	if credential.TenantID != tenantID {
		return nil, repository.ErrPermissionDenied
	}

	// Create provider
	provider, err := s.providerFactory.CreateProvider(ctx, credential.Provider, credential.Credentials)
	if err != nil {
		s.logger.Error("Failed to create provider for account listing",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to list accounts: %w", err)
	}

	// Fetch accounts
	accounts, err := provider.FetchAccounts(ctx, credential.Credentials)
	if err != nil {
		s.logger.Error("Failed to fetch accounts",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to list accounts: %w", err)
	}

	// Update account list in the credential
	err = s.credentialRepo.UpdateAccountList(ctx, integrationID, tenantID, accounts)
	if err != nil {
		s.logger.Warn("Failed to update account list",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		// Continue anyway - non-fatal error
	}

	return accounts, nil
}

// GetProviderInfo gets information about a cloud provider
func (s *cloudProviderService) GetProviderInfo(
	ctx context.Context,
	provider domain.CloudProvider,
) (*domain.CloudProviderInfo, error) {
	// Validate provider
	if !isValidProvider(provider) {
		return nil, ErrInvalidCloudProvider
	}

	// Create a dummy provider to get info
	dummyCredentials := map[string]string{}
	cloudProvider, err := s.providerFactory.CreateProvider(ctx, provider, dummyCredentials)
	if err != nil {
		// Try to return basic info if provider creation fails
		return &domain.CloudProviderInfo{
			Provider:    provider,
			DisplayName: getProviderDisplayName(provider),
			Description: "Cloud provider information not available",
		}, nil
	}

	// Get provider info
	info := cloudProvider.GetProviderInfo()
	return &info, nil
}

// GetSupportedProviders gets a list of supported cloud providers
func (s *cloudProviderService) GetSupportedProviders(ctx context.Context) []domain.CloudProvider {
	return []domain.CloudProvider{
		domain.AWS,
		domain.Azure,
		domain.GCP,
	}
}

// ImportCostData initiates a cost data import from a cloud provider
func (s *cloudProviderService) ImportCostData(
	ctx context.Context,
	tenantID string,
	provider domain.CloudProvider,
	startDate,
	endDate time.Time,
) (*domain.CostImport, error) {
	// Create context with tenant ID
	tenantCtx := domain.WithTenantID(ctx, tenantID)

	// Use the underlying cost service to import data
	// The tenant provider will use the default credentials for the tenant
	costImport, err := s.costService.ImportCostData(tenantCtx, tenantID, provider, "", startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to import cost data",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(provider)),
			logger.Time("start_date", startDate),
			logger.Time("end_date", endDate),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to import cost data: %w", err)
	}

	return costImport, nil
}

// Helper methods

// fetchAndSaveAccounts fetches cloud accounts and saves them to the credential
func (s *cloudProviderService) fetchAndSaveAccounts(ctx context.Context, credential *repository.CloudCredential) {
	// Create provider
	provider, err := s.providerFactory.CreateProvider(ctx, credential.Provider, credential.Credentials)
	if err != nil {
		s.logger.Warn("Failed to create provider for account fetching",
			logger.String("tenant_id", credential.TenantID),
			logger.String("integration_id", credential.ID),
			logger.ErrorField(err))
		return
	}

	// Fetch accounts
	accounts, err := provider.FetchAccounts(ctx, credential.Credentials)
	if err != nil {
		s.logger.Warn("Failed to fetch accounts",
			logger.String("tenant_id", credential.TenantID),
			logger.String("integration_id", credential.ID),
			logger.ErrorField(err))
		return
	}

	// Save account list
	err = s.credentialRepo.UpdateAccountList(ctx, credential.ID, credential.TenantID, accounts)
	if err != nil {
		s.logger.Warn("Failed to update account list",
			logger.String("tenant_id", credential.TenantID),
			logger.String("integration_id", credential.ID),
			logger.ErrorField(err))
	}
}

// isValidProvider checks if a provider is supported
func isValidProvider(provider domain.CloudProvider) bool {
	switch provider {
	case domain.AWS, domain.Azure, domain.GCP:
		return true
	default:
		return false
	}
}

// getProviderDisplayName returns a human-readable name for a provider
func getProviderDisplayName(provider domain.CloudProvider) string {
	switch provider {
	case domain.AWS:
		return "Amazon Web Services"
	case domain.Azure:
		return "Microsoft Azure"
	case domain.GCP:
		return "Google Cloud Platform"
	default:
		return string(provider)
	}
}
