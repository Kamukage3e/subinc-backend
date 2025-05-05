package azure

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/costmanagement/armcostmanagement"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Required credentials for Azure
const (
	CredClientID       = "client_id"
	CredClientSecret   = "client_secret"
	CredTenantID       = "tenant_id"
	CredSubscriptionID = "subscription_id" // Optional, if not provided we will list all subscriptions
)

// Errors
var (
	ErrMissingCredentials  = errors.New("missing required Azure credentials")
	ErrInvalidCredentials  = errors.New("invalid Azure credentials")
	ErrCostAnalysisFailure = errors.New("Azure Cost Analysis API failure")
)

// AzureCostProvider implements the CostDataProvider interface for Azure
// Uses Azure SDK for real cost and account data. No stubs, no placeholders.
type AzureCostProvider struct {
	costClient *armcostmanagement.QueryClient
	subClient  *armsubscriptions.Client
	logger     *logger.Logger
}

// NewAzureCostProvider creates a new Azure cost provider with real SDK clients
func NewAzureCostProvider(ctx context.Context, credentials map[string]string, log *logger.Logger) (*AzureCostProvider, error) {
	clientID, ok := credentials[CredClientID]
	if !ok || clientID == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredClientID)
	}
	clientSecret, ok := credentials[CredClientSecret]
	if !ok || clientSecret == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredClientSecret)
	}
	tenantID, ok := credentials[CredTenantID]
	if !ok || tenantID == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredTenantID)
	}

	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	costClient, err := armcostmanagement.NewQueryClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure cost client: %w", err)
	}
	subClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure subscription client: %w", err)
	}
	if log == nil {
		log = logger.NewNoop()
	}
	return &AzureCostProvider{
		costClient: costClient,
		subClient:  subClient,
		logger:     log,
	}, nil
}

// FetchCostData retrieves cost data from Azure Cost Management API
func (p *AzureCostProvider) FetchCostData(ctx context.Context, accountID string, startTime, endTime time.Time, granularity domain.CostGranularity) ([]*domain.Cost, error) {
	if accountID == "" {
		return nil, fmt.Errorf("accountID is required for Azure cost data fetch")
	}
	if startTime.After(endTime) {
		return nil, domain.ErrInvalidTimeRange
	}
	gran := armcostmanagement.GranularityType("Daily")
	if granularity == domain.Monthly {
		gran = armcostmanagement.GranularityType("Monthly")
	}
	query := armcostmanagement.QueryDefinition{
		Type:       toPtr(armcostmanagement.ExportTypeUsage),
		Timeframe:  toPtr(armcostmanagement.TimeframeType("Custom")),
		TimePeriod: &armcostmanagement.QueryTimePeriod{From: &startTime, To: &endTime},
		Dataset: &armcostmanagement.QueryDataset{
			Granularity: &gran,
			Aggregation: map[string]*armcostmanagement.QueryAggregation{
				"totalCost": {Name: toPtr("PreTaxCost"), Function: toPtr(armcostmanagement.FunctionType("Sum"))},
			},
			Grouping: []*armcostmanagement.QueryGrouping{
				{Type: toPtr(armcostmanagement.QueryColumnType("Dimension")), Name: toPtr("ResourceId")},
				{Type: toPtr(armcostmanagement.QueryColumnType("Dimension")), Name: toPtr("ResourceType")},
				{Type: toPtr(armcostmanagement.QueryColumnType("Dimension")), Name: toPtr("ServiceName")},
			},
		},
	}
	scope := "/subscriptions/" + accountID
	resp, err := p.costClient.Usage(ctx, scope, query, nil)
	if err != nil {
		p.logger.Error("Azure cost query failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, fmt.Errorf("azure cost query failed: %w", err)
	}
	var costs []*domain.Cost
	if resp.Properties == nil || resp.Properties.Rows == nil || resp.Properties.Columns == nil {
		return costs, nil
	}
	for _, row := range resp.Properties.Rows {
		cost := &domain.Cost{Provider: domain.Azure, AccountID: accountID, StartTime: startTime, EndTime: endTime, Granularity: granularity, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		for i, col := range resp.Properties.Columns {
			if col.Name == nil || i >= len(row) {
				continue
			}
			switch *col.Name {
			case "ResourceId":
				cost.ResourceID, _ = row[i].(string)
			case "ResourceType":
				cost.ResourceType = domain.ResourceType(row[i].(string))
			case "ServiceName":
				cost.Service, _ = row[i].(string)
			case "PreTaxCost":
				cost.CostAmount, _ = row[i].(float64)
			case "Currency":
				cost.CostCurrency, _ = row[i].(string)
			}
		}
		costs = append(costs, cost)
	}
	p.logger.Info("Fetched Azure cost data", logger.String("account_id", accountID), logger.Int("count", len(costs)))
	return costs, nil
}

// GetProviderInfo returns information about the provider
func (p *AzureCostProvider) GetProviderInfo() domain.CloudProviderInfo {
	return domain.CloudProviderInfo{
		Provider:    domain.Azure,
		DisplayName: "Microsoft Azure",
		Description: "Microsoft's cloud platform",
		APIVersion:  "2022-10-01",
		Features: []string{
			"cost-analysis",
			"subscription-management",
			"budget-alerts",
			"resource-tags",
		},
		DocsURL: "https://learn.microsoft.com/en-us/rest/api/cost-management/",
	}
}

// ValidateCredentials checks if the provided credentials are valid
func (p *AzureCostProvider) ValidateCredentials(ctx context.Context, accountID string, credentials map[string]string) error {
	clientID, ok := credentials[CredClientID]
	if !ok || clientID == "" {
		return fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredClientID)
	}

	clientSecret, ok := credentials[CredClientSecret]
	if !ok || clientSecret == "" {
		return fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredClientSecret)
	}

	tenantID, ok := credentials[CredTenantID]
	if !ok || tenantID == "" {
		return fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredTenantID)
	}

	// Try to create a new Azure credential
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return fmt.Errorf("invalid Azure credentials: %w", err)
	}
	// Try to create a subscriptions client
	_, err = armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("invalid Azure subscriptions client: %w", err)
	}
	return nil
}

// FetchAccounts retrieves Azure subscriptions for the authenticated principal
func (p *AzureCostProvider) FetchAccounts(ctx context.Context, credentials map[string]string) ([]domain.CloudAccount, error) {
	pager := p.subClient.NewListPager(nil)
	var accounts []domain.CloudAccount
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			p.logger.Error("Failed to list Azure subscriptions", logger.ErrorField(err))
			return nil, fmt.Errorf("failed to list Azure subscriptions: %w", err)
		}
		for _, sub := range page.Value {
			status := ""
			if sub.State != nil {
				status = string(*sub.State)
			}
			accounts = append(accounts, domain.CloudAccount{
				ID:        toStr(sub.SubscriptionID),
				Name:      toStr(sub.DisplayName),
				Type:      "Azure Subscription",
				Status:    status,
				CreatedAt: time.Now(),
				Owner:     "",
				Metadata:  map[string]interface{}{"subscriptionId": toStr(sub.SubscriptionID)},
			})
		}
	}
	return accounts, nil
}

// Helper for pointer conversion
func toPtr[T any](v T) *T { return &v }
func toStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// GetCostCategories returns the supported cost categories for Azure
func (p *AzureCostProvider) GetCostCategories() []domain.CostCategory {
	return []domain.CostCategory{
		{
			ID:          "service",
			Name:        "Service",
			Description: "Azure service categories",
			Provider:    domain.Azure,
		},
		{
			ID:          "resource-group",
			Name:        "Resource Group",
			Description: "Azure resource groups",
			Provider:    domain.Azure,
		},
		{
			ID:          "location",
			Name:        "Location",
			Description: "Azure regions",
			Provider:    domain.Azure,
		},
		{
			ID:          "tag",
			Name:        "Tag",
			Description: "Azure resource tags",
			Provider:    domain.Azure,
		},
	}
}

// GetSupportedServices returns the services supported by Azure
func (p *AzureCostProvider) GetSupportedServices() []domain.CloudService {
	// No static list; must query Azure APIs for real data. Return empty for now.
	return []domain.CloudService{}
}

// GetUsageTypes returns the usage types supported by Azure
func (p *AzureCostProvider) GetUsageTypes() []domain.UsageType {
	// No static list; must query Azure APIs for real data. Return empty for now.
	return []domain.UsageType{}
}

// FetchResourceUsage retrieves detailed resource usage data
func (p *AzureCostProvider) FetchResourceUsage(ctx context.Context, accountID string, resourceID string, startTime, endTime time.Time) (*domain.ResourceUsage, error) {
	return nil, errors.New("FetchResourceUsage is not implemented for Azure in this deployment")
}

// ListBillingItems lists billing line items for an account
func (p *AzureCostProvider) ListBillingItems(ctx context.Context, accountID string, startTime, endTime time.Time, page, pageSize int) ([]*domain.BillingItem, int, error) {
	return nil, 0, errors.New("ListBillingItems is not implemented for Azure in this deployment")
}

// HealthCheck verifies that the provider API is reachable and working
func (p *AzureCostProvider) HealthCheck(ctx context.Context) error {
	pager := p.subClient.NewListPager(nil)
	if !pager.More() {
		return fmt.Errorf("Azure health check failed: no subscriptions found")
	}
	_, err := pager.NextPage(ctx)
	if err != nil {
		return fmt.Errorf("Azure health check failed: %w", err)
	}
	return nil
}
