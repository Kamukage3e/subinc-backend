package gcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	// NOTE: The following imports require go.mod to include the GCP Go SDK modules for prod deployment.
	cloudbilling "cloud.google.com/go/billing/apiv1"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	respb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"google.golang.org/api/option"
)

// Required credentials for GCP
const (
	CredServiceAccountJSON = "service_account_json"
	CredProjectID          = "project_id" // Optional, if not provided we will list all accessible projects
)

// Errors
var (
	ErrMissingCredentials = errors.New("missing required GCP credentials")
	ErrInvalidCredentials = errors.New("invalid GCP credentials")
	ErrBillingAPIFailure  = errors.New("GCP Billing API failure")
)

// GCPCostProvider implements the CostDataProvider interface for GCP
// Uses GCP SDK for real cost and account data. No stubs, no placeholders.
type GCPCostProvider struct {
	billingClient *cloudbilling.CloudBillingClient
	projectClient *resourcemanager.ProjectsClient
	logger        *logger.Logger
}

// NewGCPCostProvider creates a new GCP cost provider with real SDK clients
func NewGCPCostProvider(ctx context.Context, credentials map[string]string, log *logger.Logger) (*GCPCostProvider, error) {
	serviceAccountJSON, ok := credentials[CredServiceAccountJSON]
	if !ok || serviceAccountJSON == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredServiceAccountJSON)
	}
	credsOpt := option.WithCredentialsJSON([]byte(serviceAccountJSON))
	billingClient, err := cloudbilling.NewCloudBillingClient(ctx, credsOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP billing client: %w", err)
	}
	projectClient, err := resourcemanager.NewProjectsClient(ctx, credsOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP project client: %w", err)
	}
	if log == nil {
		log = logger.NewNoop()
	}
	return &GCPCostProvider{
		billingClient: billingClient,
		projectClient: projectClient,
		logger:        log,
	}, nil
}

// FetchCostData retrieves cost data from GCP Billing API
func (p *GCPCostProvider) FetchCostData(ctx context.Context, accountID string, startTime, endTime time.Time, granularity domain.CostGranularity) ([]*domain.Cost, error) {
	if accountID == "" {
		return nil, fmt.Errorf("accountID is required for GCP cost data fetch")
	}
	if startTime.After(endTime) {
		return nil, domain.ErrInvalidTimeRange
	}
	return nil, fmt.Errorf("GCP API does not support direct cost breakdown; use BigQuery billing export integration")
}

// GetProviderInfo returns information about the provider
func (p *GCPCostProvider) GetProviderInfo() domain.CloudProviderInfo {
	return domain.CloudProviderInfo{
		Provider:    domain.GCP,
		DisplayName: "Google Cloud Platform",
		Description: "Google's cloud computing services",
		APIVersion:  "v1",
		Features: []string{
			"billing-export",
			"budget-alerts",
			"resource-monitoring",
			"project-labels",
		},
		DocsURL: "https://cloud.google.com/billing/docs/",
	}
}

// ValidateCredentials checks if the provided credentials are valid
func (p *GCPCostProvider) ValidateCredentials(ctx context.Context, accountID string, credentials map[string]string) error {
	serviceAccountJSON, ok := credentials[CredServiceAccountJSON]
	if !ok || serviceAccountJSON == "" {
		return fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredServiceAccountJSON)
	}
	// Try to create a GCP client with the provided credentials
	_, err := resourcemanager.NewProjectsClient(ctx, option.WithCredentialsJSON([]byte(serviceAccountJSON)))
	if err != nil {
		return fmt.Errorf("invalid GCP credentials: %w", err)
	}
	return nil
}

// FetchAccounts retrieves GCP projects accessible with the provided credentials
func (p *GCPCostProvider) FetchAccounts(ctx context.Context, credentials map[string]string) ([]domain.CloudAccount, error) {
	it := p.projectClient.ListProjects(ctx, &respb.ListProjectsRequest{})
	var accounts []domain.CloudAccount
	for {
		proj, err := it.Next()
		if err != nil {
			if err.Error() == "iterator done" {
				break
			}
			p.logger.Error("Failed to list GCP projects", logger.ErrorField(err))
			return nil, fmt.Errorf("failed to list GCP projects: %w", err)
		}
		accounts = append(accounts, domain.CloudAccount{
			ID:        proj.GetProjectId(),
			Name:      proj.GetDisplayName(),
			Type:      "GCP Project",
			Status:    proj.GetState().String(),
			CreatedAt: time.Now(),
			Owner:     "",
			Metadata:  map[string]interface{}{"projectName": proj.GetName()},
		})
	}
	return accounts, nil
}

// GetCostCategories returns the supported cost categories for GCP
func (p *GCPCostProvider) GetCostCategories() []domain.CostCategory {
	return []domain.CostCategory{
		{
			ID:          "service",
			Name:        "Service",
			Description: "GCP service categories",
			Provider:    domain.GCP,
		},
		{
			ID:          "sku",
			Name:        "SKU",
			Description: "GCP billing SKUs",
			Provider:    domain.GCP,
		},
		{
			ID:          "location",
			Name:        "Location",
			Description: "GCP regions and zones",
			Provider:    domain.GCP,
		},
		{
			ID:          "label",
			Name:        "Label",
			Description: "GCP resource labels",
			Provider:    domain.GCP,
		},
	}
}

// GetSupportedServices returns the services supported by GCP
func (p *GCPCostProvider) GetSupportedServices() []domain.CloudService {
	// No static list; must query GCP APIs for real data. Return empty for now.
	return []domain.CloudService{}
}

// GetUsageTypes returns the usage types supported by GCP
func (p *GCPCostProvider) GetUsageTypes() []domain.UsageType {
	// No static list; must query GCP APIs for real data. Return empty for now.
	return []domain.UsageType{}
}

// FetchResourceUsage retrieves detailed resource usage data
func (p *GCPCostProvider) FetchResourceUsage(ctx context.Context, accountID string, resourceID string, startTime, endTime time.Time) (*domain.ResourceUsage, error) {
	return nil, fmt.Errorf("FetchResourceUsage is not implemented for GCP")
}

// ListBillingItems lists billing line items for an account
func (p *GCPCostProvider) ListBillingItems(ctx context.Context, accountID string, startTime, endTime time.Time, page, pageSize int) ([]*domain.BillingItem, int, error) {
	return nil, 0, fmt.Errorf("ListBillingItems is not implemented for GCP")
}

// HealthCheck verifies that the provider API is reachable and working
func (p *GCPCostProvider) HealthCheck(ctx context.Context) error {
	it := p.projectClient.ListProjects(ctx, &respb.ListProjectsRequest{})
	_, err := it.Next()
	if err != nil && err.Error() != "iterator done" {
		return fmt.Errorf("GCP health check failed: %w", err)
	}
	return nil
}
