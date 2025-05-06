package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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
	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
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
	accessKeyID, ok := creds[domain.AWSAccessKeyID]
	if !ok || accessKeyID == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, domain.AWSAccessKeyID)
	}

	secretAccessKey, ok := creds[domain.AWSSecretAccessKey]
	if !ok || secretAccessKey == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrMissingCredentials, domain.AWSSecretAccessKey)
	}

	region, ok := creds[domain.AWSRegion]
	if !ok || region == "" {
		// Default to us-east-1 if not specified
		region = "us-east-1"
	}

	// Optional session token for temporary credentials
	sessionToken := creds[domain.AWSSessionToken]

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
	dims := []struct {
		Dim            cetypes.Dimension
		ID, Name, Desc string
	}{
		{cetypes.DimensionService, "service", "Service", "AWS service categories"},
		{cetypes.DimensionUsageType, "usage_type", "Usage Type", "Types of resource usage"},
		{cetypes.DimensionLinkedAccount, "account", "Account", "AWS accounts"},
		{cetypes.DimensionRegion, "region", "Region", "AWS geographical regions"},
	}
	var cats []domain.CostCategory
	for _, d := range dims {
		input := &costexplorer.GetDimensionValuesInput{Dimension: d.Dim}
		_, err := p.costExplorer.GetDimensionValues(context.Background(), input)
		if err != nil {
			p.logger.Error("Failed to fetch AWS cost category", logger.String("category", d.ID), logger.ErrorField(err))
			continue
		}
		cats = append(cats, domain.CostCategory{
			ID:          d.ID,
			Name:        d.Name,
			Description: d.Desc,
			Provider:    domain.AWS,
		})
	}
	// Add tag category (always present)
	cats = append(cats, domain.CostCategory{
		ID:          "tag",
		Name:        "Resource Tags",
		Description: "User-defined resource tags",
		Provider:    domain.AWS,
	})
	return cats
}

// GetSupportedServices returns the services supported by AWS
func (p *AWSCostProvider) GetSupportedServices() []domain.CloudService {
	// Query Cost Explorer for all unique SERVICE dimension values
	input := &costexplorer.GetDimensionValuesInput{
		Dimension: cetypes.DimensionService,
	}
	resp, err := p.costExplorer.GetDimensionValues(context.Background(), input)
	if err != nil {
		p.logger.Error("Failed to fetch AWS supported services", logger.ErrorField(err))
		return []domain.CloudService{}
	}
	var services []domain.CloudService
	for _, v := range resp.DimensionValues {
		services = append(services, domain.CloudService{
			ID:       *v.Value,
			Name:     *v.Value,
			Provider: domain.AWS,
			Category: "service",
		})
	}
	return services
}

// GetUsageTypes returns the usage types supported by AWS
func (p *AWSCostProvider) GetUsageTypes() []domain.UsageType {
	input := &costexplorer.GetDimensionValuesInput{
		Dimension: cetypes.DimensionUsageType,
	}
	resp, err := p.costExplorer.GetDimensionValues(context.Background(), input)
	if err != nil {
		p.logger.Error("Failed to fetch AWS usage types", logger.ErrorField(err))
		return []domain.UsageType{}
	}
	var usageTypes []domain.UsageType
	for _, v := range resp.DimensionValues {
		usageTypes = append(usageTypes, domain.UsageType{
			ID:       *v.Value,
			Name:     *v.Value,
			Provider: domain.AWS,
			Service:  "",
			Unit:     "",
		})
	}
	return usageTypes
}

// FetchResourceUsage retrieves detailed resource usage data for a specific AWS resource
func (p *AWSCostProvider) FetchResourceUsage(ctx context.Context, accountID string, resourceID string, startTime, endTime time.Time) (*domain.ResourceUsage, error) {
	if resourceID == "" {
		return nil, fmt.Errorf("resourceID is required for AWS resource usage fetch")
	}
	if startTime.After(endTime) {
		return nil, domain.ErrInvalidTimeRange
	}
	startDate := startTime.Format("2006-01-02")
	endDate := endTime.Format("2006-01-02")
	timePeriod := &cetypes.DateInterval{
		Start: awssdk.String(startDate),
		End:   awssdk.String(endDate),
	}
	input := &costexplorer.GetCostAndUsageInput{
		Granularity: cetypes.GranularityDaily,
		TimePeriod:  timePeriod,
		Metrics:     []string{"UnblendedCost", "UsageQuantity"},
		GroupBy: []cetypes.GroupDefinition{
			{
				Type: cetypes.GroupDefinitionTypeDimension,
				Key:  awssdk.String("RESOURCE_ID"),
			},
		},
		Filter: &cetypes.Expression{
			Dimensions: &cetypes.DimensionValues{
				Key:    cetypes.DimensionResourceId,
				Values: []string{resourceID},
			},
		},
	}
	resp, err := p.costExplorer.GetCostAndUsage(ctx, input)
	if err != nil {
		p.logger.Error("Failed to fetch AWS resource usage", logger.ErrorField(err), logger.String("resource_id", resourceID))
		return nil, fmt.Errorf("failed to fetch AWS resource usage: %w", err)
	}
	usage := &domain.ResourceUsage{
		ResourceID: resourceID,
		Provider:   domain.AWS,
		AccountID:  accountID,
		StartTime:  startTime,
		EndTime:    endTime,
		Metrics:    make(map[string]float64),
	}
	for _, resultByTime := range resp.ResultsByTime {
		for _, group := range resultByTime.Groups {
			if len(group.Keys) > 0 && group.Keys[0] == resourceID {
				if cost, ok := group.Metrics["UnblendedCost"]; ok && cost.Amount != nil {
					c, _ := parseFloat(*cost.Amount)
					usage.Metrics["cost"] += c
				}
				if usageMetric, ok := group.Metrics["UsageQuantity"]; ok && usageMetric.Amount != nil {
					u, _ := parseFloat(*usageMetric.Amount)
					usage.Metrics["usage"] += u
				}
				if cost, ok := group.Metrics["UnblendedCost"]; ok && cost.Unit != nil {
					// Store currency as a string in a float64 map (not ideal, but matches interface)
					// Use a convention: currency code as a negative float (e.g., -840 for USD)
					// Or just skip, as currency is always USD for AWS
				}
			}
		}
	}
	return usage, nil
}

// ListBillingItems lists billing line items for an account
func (p *AWSCostProvider) ListBillingItems(ctx context.Context, accountID string, startTime, endTime time.Time, page, pageSize int) ([]*domain.BillingItem, int, error) {
	if accountID == "" {
		return nil, 0, fmt.Errorf("accountID is required for AWS billing items")
	}
	if startTime.After(endTime) {
		return nil, 0, domain.ErrInvalidTimeRange
	}
	startDate := startTime.Format("2006-01-02")
	endDate := endTime.Format("2006-01-02")
	timePeriod := &cetypes.DateInterval{
		Start: awssdk.String(startDate),
		End:   awssdk.String(endDate),
	}
	input := &costexplorer.GetCostAndUsageInput{
		Granularity: cetypes.GranularityDaily,
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
		Filter: &cetypes.Expression{
			Dimensions: &cetypes.DimensionValues{
				Key:    cetypes.DimensionLinkedAccount,
				Values: []string{accountID},
			},
		},
	}
	resp, err := p.costExplorer.GetCostAndUsage(ctx, input)
	if err != nil {
		p.logger.Error("Failed to fetch AWS billing items", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("failed to fetch AWS billing items: %w", err)
	}
	var items []*domain.BillingItem
	for _, resultByTime := range resp.ResultsByTime {
		for _, group := range resultByTime.Groups {
			var service, resourceID string
			if len(group.Keys) > 0 {
				service = group.Keys[0]
			}
			if len(group.Keys) > 1 {
				resourceID = group.Keys[1]
			}
			costAmount := 0.0
			if cost, ok := group.Metrics["UnblendedCost"]; ok && cost.Amount != nil {
				costAmount, _ = parseFloat(*cost.Amount)
			}
			usageQuantity := 0.0
			if usage, ok := group.Metrics["UsageQuantity"]; ok && usage.Amount != nil {
				usageQuantity, _ = parseFloat(*usage.Amount)
			}
			var startTimeVal, endTimeVal time.Time
			if resultByTime.TimePeriod.Start != nil {
				startTimeVal, _ = time.Parse("2006-01-02", *resultByTime.TimePeriod.Start)
			}
			if resultByTime.TimePeriod.End != nil {
				endTimeVal, _ = time.Parse("2006-01-02", *resultByTime.TimePeriod.End)
			}
			item := &domain.BillingItem{
				ID:            uuid.New().String(),
				AccountID:     accountID,
				Provider:      domain.AWS,
				Description:   fmt.Sprintf("%s %s", service, resourceID),
				Service:       service,
				ResourceID:    resourceID,
				UsageType:     determineUsageType(service, resourceID),
				UsageQuantity: usageQuantity,
				UsageUnit:     determineUsageUnit(service, resourceID),
				CostAmount:    costAmount,
				CostCurrency:  determineCurrency(group.Metrics),
				StartTime:     startTimeVal,
				EndTime:       endTimeVal,
			}
			items = append(items, item)
		}
	}
	total := len(items)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 100
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		return []*domain.BillingItem{}, total, nil
	}
	if end > total {
		end = total
	}
	return items[start:end], total, nil
}

// HealthCheck verifies that the AWS Cost Explorer API is reachable
func (p *AWSCostProvider) HealthCheck(ctx context.Context) error {
	_, err := p.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("AWS health check failed: %w", err)
	}
	return nil
}

// ListResources implements ResourceInventoryProvider for AWS
func (p *AWSCostProvider) ListResources(ctx context.Context, accountID string, credentials map[string]string) ([]architecture.ResourceNode, error) {
	if credentials == nil {
		return nil, ErrMissingCredentials
	}
	resources, err := architecture.ScanAWSResourcesFormer2Style(ctx, credentials, credentials[domain.AWSRegion])
	if err != nil {
		p.logger.Error("Failed to scan AWS resources", logger.ErrorField(err))
		return nil, err
	}
	return resources, nil
}

// Helper functions

// parseFloat safely parses a string to float64
func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// determineResourceType infers resource type from service and resource ID using a map-based, extensible approach
func determineResourceType(service, resourceID string) domain.ResourceType {
	// Map of patterns to resource types for extensibility
	var typePatterns = []struct {
		Pattern string
		Type    domain.ResourceType
	}{
		{"^i-", domain.Compute},
		{"^vol-", domain.Storage},
		{"^db-", domain.Database},
		{"ec2", domain.Compute},
		{"s3", domain.Storage},
		{"rds", domain.Database},
		{"dynamodb", domain.Database},
		{"vpc", domain.Network},
		{"cloudfront", domain.Network},
	}
	serviceLower := strings.ToLower(service)
	for _, entry := range typePatterns {
		if matched, _ := regexp.MatchString(entry.Pattern, resourceID); matched {
			return entry.Type
		}
		if strings.Contains(serviceLower, entry.Pattern) {
			return entry.Type
		}
	}
	return domain.Other
}

// determineRegionFromResourceID extracts region from AWS resource ID or ARN
func determineRegionFromResourceID(resourceID string) string {
	// ARN format: arn:partition:service:region:account-id:resource
	if strings.HasPrefix(resourceID, "arn:") {
		parts := strings.Split(resourceID, ":")
		if len(parts) >= 4 {
			return parts[3]
		}
	}
	// Try to match region in known resource ID patterns (e.g., vol-<region>-<id>)
	regionPattern := regexp.MustCompile(`[a-z]{2}-[a-z]+-\d`)
	if match := regionPattern.FindString(resourceID); match != "" {
		return match
	}
	return ""
}

// determineUsageType infers usage type from service and resource ID, using a scalable map-based approach
func determineUsageType(service, resourceID string) string {
	service = strings.ToLower(service)
	usageTypeMap := map[string]string{
		"ec2":        "BoxUsage",
		"s3":         "Storage",
		"rds":        "DBInstanceUsage",
		"lambda":     "LambdaUsage",
		"dynamodb":   "ReadWriteCapacity",
		"vpc":        "VpcUsage",
		"cloudfront": "DataTransfer",
		"elb":        "LoadBalancerUsage",
		"redshift":   "NodeUsage",
		"glacier":    "ArchiveStorage",
		"kms":        "KeyUsage",
	}
	for pattern, usageType := range usageTypeMap {
		if strings.Contains(service, pattern) {
			return usageType
		}
	}
	return ""
}

// determineUsageUnit infers usage unit from service and resource ID, using a scalable map-based approach
func determineUsageUnit(service, resourceID string) string {
	service = strings.ToLower(service)
	usageUnitMap := map[string]string{
		"ec2":        "Hours",
		"s3":         "GB",
		"rds":        "Hours",
		"lambda":     "Requests",
		"dynamodb":   "ReadWriteUnits",
		"vpc":        "Hours",
		"cloudfront": "GB",
		"elb":        "Hours",
		"redshift":   "NodeHours",
		"glacier":    "GB-Months",
		"kms":        "Requests",
	}
	for pattern, usageUnit := range usageUnitMap {
		if strings.Contains(service, pattern) {
			return usageUnit
		}
	}
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
