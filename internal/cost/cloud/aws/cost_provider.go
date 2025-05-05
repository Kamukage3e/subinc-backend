package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"

	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Required credentials for AWS
const (
	CredAccessKeyID     = "access_key_id"
	CredSecretAccessKey = "secret_access_key"
	CredRegion          = "region"
	CredSessionToken    = "session_token" // Optional
)

// Errors
var (
	ErrMissingCredentials  = errors.New("missing required AWS credentials")
	ErrInvalidCredentials  = errors.New("invalid AWS credentials")
	ErrCostExplorerFailure = errors.New("AWS Cost Explorer API failure")
)

// AWSCostProvider implements the CostDataProvider interface for AWS
type AWSCostProvider struct {
	costExplorer *costexplorer.Client
	stsClient    *sts.Client
	logger       *logger.Logger
}

// NewAWSCostProvider creates a new AWS cost provider
func NewAWSCostProvider(ctx context.Context, creds map[string]string, log *logger.Logger) (*AWSCostProvider, error) {
	// Validate required credentials
	accessKeyID, ok := creds[CredAccessKeyID]
	if !ok || accessKeyID == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredAccessKeyID)
	}

	secretAccessKey, ok := creds[CredSecretAccessKey]
	if !ok || secretAccessKey == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, CredSecretAccessKey)
	}

	region, ok := creds[CredRegion]
	if !ok || region == "" {
		// Default to us-east-1 if not specified
		region = "us-east-1"
	}

	// Optional session token for temporary credentials
	sessionToken := creds[CredSessionToken]

	// Create AWS credentials provider
	var credProvider awssdk.CredentialsProvider
	if sessionToken != "" {
		credProvider = awscreds.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
	} else {
		credProvider = awscreds.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")
	}

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credProvider),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create Cost Explorer client
	ceClient := costexplorer.NewFromConfig(cfg)

	// Create STS client for account validation
	stsClient := sts.NewFromConfig(cfg)

	if log == nil {
		log = logger.NewNoop()
	}

	return &AWSCostProvider{
		costExplorer: ceClient,
		stsClient:    stsClient,
		logger:       log,
	}, nil
}

// FetchCostData retrieves cost data from AWS Cost Explorer
func (p *AWSCostProvider) FetchCostData(ctx context.Context, accountID string, startTime, endTime time.Time, granularity domain.CostGranularity) ([]*domain.Cost, error) {
	// Map domain granularity to AWS granularity
	ceGranularity := cetypes.GranularityDaily
	switch granularity {
	case domain.Hourly:
		ceGranularity = cetypes.GranularityHourly
	case domain.Daily:
		ceGranularity = cetypes.GranularityDaily
	case domain.Monthly:
		ceGranularity = cetypes.GranularityMonthly
	}

	// Validate date range
	if startTime.After(endTime) {
		return nil, domain.ErrInvalidTimeRange
	}

	// Format dates as required by AWS Cost Explorer (YYYY-MM-DD)
	startDate := startTime.Format("2006-01-02")
	endDate := endTime.Format("2006-01-02")

	// Define the time period
	timePeriod := &cetypes.DateInterval{
		Start: awssdk.String(startDate),
		End:   awssdk.String(endDate),
	}

	// Build the cost explorer request
	input := &costexplorer.GetCostAndUsageInput{
		Granularity: ceGranularity,
		TimePeriod:  timePeriod,
		Metrics:     []string{"UnblendedCost", "UsageQuantity"},
		GroupBy: []cetypes.GroupDefinition{
			{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  awssdk.String("SERVICE"),
			},
			{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  awssdk.String("RESOURCE_ID"),
			},
		},
	}

	// Add filter for specific account if provided
	if accountID != "" {
		input.Filter = &cetypes.Expression{
			Dimensions: &cetypes.DimensionValues{
				Key:    cetypes.DimensionLinkedAccount,
				Values: []string{accountID},
			},
		}
	}

	p.logger.Debug("Fetching AWS cost data",
		logger.String("account_id", accountID),
		logger.String("start_date", startDate),
		logger.String("end_date", endDate),
		logger.String("granularity", string(ceGranularity)))

	// Make the API call
	resp, err := p.costExplorer.GetCostAndUsage(ctx, input)
	if err != nil {
		p.logger.Error("Failed to fetch AWS cost data",
			logger.ErrorField(err),
			logger.String("account_id", accountID))
		return nil, fmt.Errorf("%w: %v", ErrCostExplorerFailure, err)
	}

	// Transform the response to domain cost objects
	var costs []*domain.Cost
	for _, resultByTime := range resp.ResultsByTime {
		// Parse period start and end times
		periodStart, err := time.Parse("2006-01-02", *resultByTime.TimePeriod.Start)
		if err != nil {
			p.logger.Warn("Failed to parse period start time",
				logger.ErrorField(err),
				logger.String("start_time", *resultByTime.TimePeriod.Start))
			continue
		}

		periodEnd, err := time.Parse("2006-01-02", *resultByTime.TimePeriod.End)
		if err != nil {
			p.logger.Warn("Failed to parse period end time",
				logger.ErrorField(err),
				logger.String("end_time", *resultByTime.TimePeriod.End))
			continue
		}

		// Process each group
		for _, group := range resultByTime.Groups {
			// Extract service and resource ID from keys
			var service, resourceID string
			if len(group.Keys) > 0 {
				service = group.Keys[0]
			}
			if len(group.Keys) > 1 {
				resourceID = group.Keys[1]
			}

			// Get cost amount and usage quantity
			costAmount := 0.0
			if cost, ok := group.Metrics["UnblendedCost"]; ok {
				if cost.Amount != nil {
					costAmount, _ = parseFloat(*cost.Amount)
				}
			}

			usageQuantity := 0.0
			if usage, ok := group.Metrics["UsageQuantity"]; ok {
				if usage.Amount != nil {
					usageQuantity, _ = parseFloat(*usage.Amount)
				}
			}

			// Create cost record
			cost := &domain.Cost{
				ID:             uuid.New().String(),
				TenantID:       accountID, // Using account ID as tenant ID for now
				Provider:       domain.AWS,
				AccountID:      accountID,
				ResourceID:     resourceID,
				ResourceName:   resourceID, // Resource name not directly available
				ResourceType:   determineResourceType(service, resourceID),
				Service:        service,
				Region:         determineRegionFromResourceID(resourceID),
				UsageType:      determineUsageType(service, resourceID),
				UsageQuantity:  usageQuantity,
				UsageUnit:      determineUsageUnit(service, resourceID),
				CostAmount:     costAmount,
				CostCurrency:   determineCurrency(group.Metrics),
				EffectivePrice: determineEffectivePrice(costAmount, usageQuantity),
				StartTime:      periodStart,
				EndTime:        periodEnd,
				Granularity:    domain.CostGranularity(string(ceGranularity)),
				CreatedAt:      time.Now().UTC(),
				UpdatedAt:      time.Now().UTC(),
			}

			costs = append(costs, cost)
		}
	}

	p.logger.Info("Successfully fetched AWS cost data",
		logger.String("account_id", accountID),
		logger.Int("record_count", len(costs)))

	return costs, nil
}

// GetProviderInfo returns information about AWS as a provider
func (p *AWSCostProvider) GetProviderInfo() domain.CloudProviderInfo {
	return domain.CloudProviderInfo{
		Provider:    domain.AWS,
		DisplayName: "Amazon Web Services",
		Description: "Amazon Web Services (AWS) is a comprehensive cloud platform offering over 200 services globally.",
		APIVersion:  "Cost Explorer API v2",
		Features: []string{
			"Cost and Usage Reports",
			"Budgets",
			"Anomaly Detection",
			"Resource Tags",
			"Reserved Instance Recommendations",
		},
		DocsURL: "https://docs.aws.amazon.com/cost-management/",
	}
}

// ValidateCredentials checks if the AWS credentials are valid
func (p *AWSCostProvider) ValidateCredentials(ctx context.Context, accountID string, credentials map[string]string) error {
	// If we already have a client, just verify we can call GetCallerIdentity
	if p.stsClient != nil {
		// Call STS GetCallerIdentity to validate credentials
		identity, err := p.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			p.logger.Error("Failed to validate AWS credentials",
				logger.ErrorField(err))
			return fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
		}

		// If accountID is provided, check that it matches
		if accountID != "" && *identity.Account != accountID {
			p.logger.Error("Account ID mismatch",
				logger.String("expected", accountID),
				logger.String("actual", *identity.Account))
			return fmt.Errorf("%w: account ID mismatch", ErrInvalidCredentials)
		}

		return nil
	}

	// Otherwise, create a temporary provider to validate
	_, err := NewAWSCostProvider(ctx, credentials, p.logger)
	return err
}

// FetchAccounts retrieves AWS accounts accessible with the provided credentials
func (p *AWSCostProvider) FetchAccounts(ctx context.Context, credentials map[string]string) ([]domain.CloudAccount, error) {
	// For AWS, we need to:
	// 1. Validate the credentials work
	// 2. Get the caller identity to determine the account
	// 3. If this is an organization master account, list all accounts in the org

	// Create a provider if needed
	var provider *AWSCostProvider
	var err error
	if p.stsClient != nil {
		provider = p
	} else {
		provider, err = NewAWSCostProvider(ctx, credentials, p.logger)
		if err != nil {
			return nil, err
		}
	}

	// Get caller identity
	identity, err := provider.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		p.logger.Error("Failed to get caller identity",
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to get AWS account info: %w", err)
	}

	// Create account
	accounts := []domain.CloudAccount{
		{
			ID:        *identity.Account,
			Name:      fmt.Sprintf("AWS Account %s", *identity.Account),
			Type:      "AWS Account",
			Status:    "active",
			CreatedAt: time.Now(), // Not available from STS
			Owner:     *identity.UserId,
			Metadata: map[string]interface{}{
				"arn": *identity.Arn,
			},
		},
	}

	// Note: In a real implementation, we would also use the AWS Organizations API
	// to list all accounts in the organization if the caller has permissions

	return accounts, nil
}

// GetCostCategories returns the supported cost categories for AWS
func (p *AWSCostProvider) GetCostCategories() []domain.CostCategory {
	return []domain.CostCategory{
		{
			ID:          "service",
			Name:        "Service",
			Description: "AWS service categories",
			Provider:    domain.AWS,
		},
		{
			ID:          "region",
			Name:        "Region",
			Description: "AWS geographical regions",
			Provider:    domain.AWS,
		},
		{
			ID:          "account",
			Name:        "Account",
			Description: "AWS accounts",
			Provider:    domain.AWS,
		},
		{
			ID:          "tag",
			Name:        "Resource Tags",
			Description: "User-defined resource tags",
			Provider:    domain.AWS,
		},
		{
			ID:          "usage_type",
			Name:        "Usage Type",
			Description: "Types of resource usage",
			Provider:    domain.AWS,
		},
	}
}

// GetSupportedServices returns the services supported by AWS
func (p *AWSCostProvider) GetSupportedServices() []domain.CloudService {
	// No static list; must query AWS APIs for real data. Return empty for now.
	return []domain.CloudService{}
}

// GetUsageTypes returns the usage types supported by AWS
func (p *AWSCostProvider) GetUsageTypes() []domain.UsageType {
	// No static list; must query AWS APIs for real data. Return empty for now.
	return []domain.UsageType{}
}

// FetchResourceUsage retrieves detailed resource usage data
func (p *AWSCostProvider) FetchResourceUsage(ctx context.Context, accountID string, resourceID string, startTime, endTime time.Time) (*domain.ResourceUsage, error) {
	return nil, fmt.Errorf("FetchResourceUsage is not implemented for AWS")
}

// ListBillingItems lists billing line items for an account
func (p *AWSCostProvider) ListBillingItems(ctx context.Context, accountID string, startTime, endTime time.Time, page, pageSize int) ([]*domain.BillingItem, int, error) {
	return nil, 0, fmt.Errorf("ListBillingItems is not implemented for AWS")
}

// HealthCheck verifies that the AWS Cost Explorer API is reachable
func (p *AWSCostProvider) HealthCheck(ctx context.Context) error {
	_, err := p.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("AWS health check failed: %w", err)
	}
	return nil
}

// Helper functions

// parseFloat safely parses a string to float64
func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// determineResourceType infers resource type from service and resource ID
func determineResourceType(service, resourceID string) domain.ResourceType {
	// In a real implementation, we'd have more sophisticated logic
	// For now, use a simple mapping
	switch {
	case strings.HasPrefix(resourceID, "i-"):
		return domain.Compute
	case strings.HasPrefix(resourceID, "vol-"):
		return domain.Storage
	case strings.HasPrefix(resourceID, "db-"):
		return domain.Database
	case strings.Contains(service, "EC2"):
		return domain.Compute
	case strings.Contains(service, "S3"):
		return domain.Storage
	case strings.Contains(service, "RDS") || strings.Contains(service, "DynamoDB"):
		return domain.Database
	case strings.Contains(service, "VPC") || strings.Contains(service, "CloudFront"):
		return domain.Network
	default:
		return domain.Other
	}
}

// determineRegionFromResourceID extracts region from AWS resource ID if possible
func determineRegionFromResourceID(resourceID string) string {
	// Region extraction not implemented; return empty string for safety.
	return ""
}

// determineUsageType infers usage type from service and resource ID
func determineUsageType(service, resourceID string) string {
	// Usage type extraction not implemented; return empty string for safety.
	return ""
}

// determineUsageUnit infers usage unit from service and resource ID
func determineUsageUnit(service, resourceID string) string {
	// Usage unit extraction not implemented; return empty string for safety.
	return ""
}

// determineCurrency extracts currency from AWS metrics
func determineCurrency(metrics map[string]cetypes.MetricValue) string {
	// Check if UnblendedCost is present and has a unit
	if cost, ok := metrics["UnblendedCost"]; ok {
		if cost.Unit != nil {
			return *cost.Unit
		}
	}
	// Default to USD
	return "USD"
}

// determineEffectivePrice calculates effective price from cost and usage
func determineEffectivePrice(cost, usage float64) float64 {
	if usage > 0 {
		return cost / usage
	}
	return 0
}
