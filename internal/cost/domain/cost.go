package domain

import (
	"time"
)

// CloudProvider represents supported cloud providers
type CloudProvider string

const (
	// AWS is Amazon Web Services
	AWS CloudProvider = "aws"
	// Azure is Microsoft Azure
	Azure CloudProvider = "azure"
	// GCP is Google Cloud Platform
	GCP CloudProvider = "gcp"
)

// CostGranularity represents the time granularity of cost data
type CostGranularity string

const (
	// Hourly granularity for cost data
	Hourly CostGranularity = "hourly"
	// Daily granularity for cost data
	Daily CostGranularity = "daily"
	// Monthly granularity for cost data
	Monthly CostGranularity = "monthly"
)

// ResourceType represents the type of cloud resource
type ResourceType string

const (
	// Compute resources (EC2, VM, etc.)
	Compute ResourceType = "compute"
	// Storage resources (S3, Blob Storage, etc.)
	Storage ResourceType = "storage"
	// Database resources (RDS, CosmosDB, etc.)
	Database ResourceType = "database"
	// Network resources (VPC, Load Balancers, etc.)
	Network ResourceType = "network"
	// Analytics resources (Redshift, BigQuery, etc.)
	Analytics ResourceType = "analytics"
	// Other resources that don't fit the above categories
	Other ResourceType = "other"
)

// Cost represents a cost record for a cloud resource
type Cost struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	Provider       CloudProvider     `json:"provider"`
	AccountID      string            `json:"account_id"`      // AWS Account ID, Azure Subscription ID, or GCP Project ID
	ResourceID     string            `json:"resource_id"`     // Unique identifier of the resource
	ResourceName   string            `json:"resource_name"`   // Human-readable name of the resource
	ResourceType   ResourceType      `json:"resource_type"`   // Type of resource (EC2, S3, etc.)
	Service        string            `json:"service"`         // Cloud service (e.g., EC2, S3, Lambda)
	Region         string            `json:"region"`          // Cloud region (e.g., us-east-1)
	UsageType      string            `json:"usage_type"`      // Type of usage (e.g., BoxUsage, DataTransfer)
	UsageQuantity  float64           `json:"usage_quantity"`  // Quantity of usage
	UsageUnit      string            `json:"usage_unit"`      // Unit of measurement (e.g., GB, hours)
	CostAmount     float64           `json:"cost_amount"`     // Cost amount in USD
	CostCurrency   string            `json:"cost_currency"`   // Currency of the cost (e.g., USD)
	EffectivePrice float64           `json:"effective_price"` // Price per unit
	StartTime      time.Time         `json:"start_time"`      // Start time of the cost period
	EndTime        time.Time         `json:"end_time"`        // End time of the cost period
	Granularity    CostGranularity   `json:"granularity"`     // Granularity of the cost data
	Tags           map[string]string `json:"tags"`            // Resource tags
	Labels         map[string]string `json:"labels"`          // Additional labels/metadata
	CreatedAt      time.Time         `json:"created_at"`      // When this record was created
	UpdatedAt      time.Time         `json:"updated_at"`      // When this record was last updated
}

// Validate validates a cost record
func (c *Cost) Validate() error {
	if c.TenantID == "" {
		return ErrInvalidTenant
	}

	switch c.Provider {
	case AWS, Azure, GCP:
		// Valid provider
	default:
		return ErrInvalidProvider
	}

	if c.StartTime.After(c.EndTime) {
		return ErrInvalidTimeRange
	}

	switch c.Granularity {
	case Hourly, Daily, Monthly:
		// Valid granularity
	default:
		return ErrInvalidGranularity
	}

	if c.ResourceID == "" {
		return ErrInvalidResource
	}

	return nil
}

// CostSummary represents aggregated cost data
type CostSummary struct {
	TenantID     string                 `json:"tenant_id"`
	Provider     CloudProvider          `json:"provider,omitempty"`
	AccountID    string                 `json:"account_id,omitempty"`
	Service      string                 `json:"service,omitempty"`
	ResourceType ResourceType           `json:"resource_type,omitempty"`
	Region       string                 `json:"region,omitempty"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	Granularity  CostGranularity        `json:"granularity"`
	TotalCost    float64                `json:"total_cost"`
	Currency     string                 `json:"currency"`
	GroupBy      []string               `json:"group_by,omitempty"`
	Groups       map[string]CostSummary `json:"groups,omitempty"`
}

// CostQuery represents parameters for querying cost data
type CostQuery struct {
	TenantID      string            `json:"tenant_id"`
	Providers     []CloudProvider   `json:"providers,omitempty"`
	AccountIDs    []string          `json:"account_ids,omitempty"`
	ResourceIDs   []string          `json:"resource_ids,omitempty"`
	ResourceTypes []ResourceType    `json:"resource_types,omitempty"`
	Services      []string          `json:"services,omitempty"`
	Regions       []string          `json:"regions,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	StartTime     time.Time         `json:"start_time"`
	EndTime       time.Time         `json:"end_time"`
	Granularity   CostGranularity   `json:"granularity"`
	GroupBy       []string          `json:"group_by,omitempty"`
	Page          int               `json:"page,omitempty"`
	PageSize      int               `json:"page_size,omitempty"`
	SortBy        string            `json:"sort_by,omitempty"`
	SortDirection string            `json:"sort_direction,omitempty"`
}

// Validate validates a cost query
func (q *CostQuery) Validate() error {
	if q.TenantID == "" {
		return ErrInvalidTenant
	}

	if q.StartTime.After(q.EndTime) {
		return ErrInvalidTimeRange
	}

	switch q.Granularity {
	case Hourly, Daily, Monthly:
		// Valid granularity
	default:
		return ErrInvalidGranularity
	}

	return nil
}

// CostImport represents a cost data import from a cloud provider
type CostImport struct {
	ID           string        `json:"id"`
	TenantID     string        `json:"tenant_id"`
	Provider     CloudProvider `json:"provider"`
	AccountID    string        `json:"account_id"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Status       string        `json:"status"` // pending, in_progress, completed, failed
	RecordsCount int           `json:"records_count"`
	ErrorMessage string        `json:"error_message,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	CompletedAt  *time.Time    `json:"completed_at,omitempty"`
}

// Forecast represents a cost forecast
type Forecast struct {
	ID             string        `json:"id"`
	TenantID       string        `json:"tenant_id"`
	Provider       CloudProvider `json:"provider,omitempty"`
	AccountID      string        `json:"account_id,omitempty"`
	Service        string        `json:"service,omitempty"`
	ResourceType   ResourceType  `json:"resource_type,omitempty"`
	StartTime      time.Time     `json:"start_time"`
	EndTime        time.Time     `json:"end_time"`
	ForecastedCost float64       `json:"forecasted_cost"`
	ActualCost     float64       `json:"actual_cost"`
	Currency       string        `json:"currency"`
	Confidence     float64       `json:"confidence"`
	Algorithm      string        `json:"algorithm"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// Budget represents a cost budget
type Budget struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Provider    CloudProvider     `json:"provider,omitempty"`
	AccountID   string            `json:"account_id,omitempty"`
	Service     string            `json:"service,omitempty"`
	Amount      float64           `json:"amount"`
	Currency    string            `json:"currency"`
	Period      string            `json:"period"` // monthly, quarterly, yearly
	StartTime   time.Time         `json:"start_time"`
	EndTime     *time.Time        `json:"end_time,omitempty"`
	Alerts      []BudgetAlert     `json:"alerts,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// BudgetAlert represents an alert for a budget
type BudgetAlert struct {
	Threshold        float64  `json:"threshold"`         // percentage of budget (e.g., 80 for 80%)
	ThresholdType    string   `json:"threshold_type"`    // percentage, absolute
	NotificationType string   `json:"notification_type"` // email, slack, webhook
	Recipients       []string `json:"recipients,omitempty"`
	Enabled          bool     `json:"enabled"`
}

// Anomaly represents a cost anomaly
type Anomaly struct {
	ID             string        `json:"id"`
	TenantID       string        `json:"tenant_id"`
	Provider       CloudProvider `json:"provider"`
	AccountID      string        `json:"account_id,omitempty"`
	ResourceID     string        `json:"resource_id,omitempty"`
	Service        string        `json:"service,omitempty"`
	DetectedAt     time.Time     `json:"detected_at"`
	StartTime      time.Time     `json:"start_time"`
	EndTime        time.Time     `json:"end_time"`
	ExpectedCost   float64       `json:"expected_cost"`
	ActualCost     float64       `json:"actual_cost"`
	Deviation      float64       `json:"deviation"` // percentage
	Severity       string        `json:"severity"`  // low, medium, high
	Status         string        `json:"status"`    // open, acknowledged, resolved, false_positive
	RootCause      string        `json:"root_cause,omitempty"`
	Recommendation string        `json:"recommendation,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}
