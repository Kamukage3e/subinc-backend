package domain

import (
	"time"
)

// CloudProviderInfo contains metadata about a cloud provider
type CloudProviderInfo struct {
	// Provider is the cloud provider identifier
	Provider CloudProvider `json:"provider"`

	// DisplayName is the human-readable name of the provider
	DisplayName string `json:"display_name"`

	// Description is a brief description of the provider
	Description string `json:"description"`

	// APIVersion is the version of the provider's API being used
	APIVersion string `json:"api_version"`

	// Features is a list of supported features
	Features []string `json:"features"`

	// DocsURL is a URL to provider documentation
	DocsURL string `json:"docs_url"`
}

// CloudAccount represents an account/subscription/project in a cloud provider
type CloudAccount struct {
	// ID is the unique identifier of the account in the provider
	ID string `json:"id"`

	// Name is the human-readable name of the account
	Name string `json:"name"`

	// Type is the type of account (e.g., "AWS Account", "Azure Subscription", "GCP Project")
	Type string `json:"type"`

	// Status indicates if the account is active, suspended, etc.
	Status string `json:"status"`

	// CreatedAt is when the account was created
	CreatedAt time.Time `json:"created_at"`

	// Owner is the account owner information
	Owner string `json:"owner,omitempty"`

	// Tags are key-value pairs associated with the account
	Tags map[string]string `json:"tags,omitempty"`

	// Metadata contains provider-specific account details
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// CostCategory represents a category for costs in a cloud provider
type CostCategory struct {
	// ID is the unique identifier of the category
	ID string `json:"id"`

	// Name is the human-readable name of the category
	Name string `json:"name"`

	// Description is a brief description of the category
	Description string `json:"description"`

	// Provider is the cloud provider this category belongs to
	Provider CloudProvider `json:"provider"`
}

// CloudService represents a service offered by a cloud provider
type CloudService struct {
	// ID is the unique identifier of the service
	ID string `json:"id"`

	// Name is the human-readable name of the service
	Name string `json:"name"`

	// Description is a brief description of the service
	Description string `json:"description"`

	// Provider is the cloud provider this service belongs to
	Provider CloudProvider `json:"provider"`

	// Category is the service category
	Category string `json:"category"`
}

// UsageType represents a type of usage in a cloud provider
type UsageType struct {
	// ID is the unique identifier of the usage type
	ID string `json:"id"`

	// Name is the human-readable name of the usage type
	Name string `json:"name"`

	// Description is a brief description of the usage type
	Description string `json:"description"`

	// Provider is the cloud provider this usage type belongs to
	Provider CloudProvider `json:"provider"`

	// Service is the service this usage type belongs to
	Service string `json:"service"`

	// Unit is the unit of measurement (e.g., "GB", "hours")
	Unit string `json:"unit"`
}

// ResourceUsage contains detailed usage data for a specific resource
type ResourceUsage struct {
	// ResourceID is the unique identifier of the resource
	ResourceID string `json:"resource_id"`

	// ResourceName is the human-readable name of the resource
	ResourceName string `json:"resource_name"`

	// ResourceType is the type of resource
	ResourceType ResourceType `json:"resource_type"`

	// Provider is the cloud provider
	Provider CloudProvider `json:"provider"`

	// AccountID is the account/subscription/project ID
	AccountID string `json:"account_id"`

	// StartTime is the start of the usage period
	StartTime time.Time `json:"start_time"`

	// EndTime is the end of the usage period
	EndTime time.Time `json:"end_time"`

	// Metrics are usage metrics for the resource
	Metrics map[string]float64 `json:"metrics"`

	// Tags are resource tags
	Tags map[string]string `json:"tags,omitempty"`
}

// BillingItem represents a line item in a cloud provider bill
type BillingItem struct {
	// ID is the unique identifier of the billing item
	ID string `json:"id"`

	// InvoiceID is the ID of the invoice this item belongs to
	InvoiceID string `json:"invoice_id,omitempty"`

	// AccountID is the account/subscription/project ID
	AccountID string `json:"account_id"`

	// Provider is the cloud provider
	Provider CloudProvider `json:"provider"`

	// Description is a human-readable description of the item
	Description string `json:"description"`

	// Service is the service this item relates to
	Service string `json:"service"`

	// ResourceID is the resource this item relates to, if applicable
	ResourceID string `json:"resource_id,omitempty"`

	// UsageType is the type of usage
	UsageType string `json:"usage_type"`

	// UsageQuantity is the quantity of usage
	UsageQuantity float64 `json:"usage_quantity"`

	// UsageUnit is the unit of measurement
	UsageUnit string `json:"usage_unit"`

	// CostAmount is the cost amount
	CostAmount float64 `json:"cost_amount"`

	// CostCurrency is the currency of the cost
	CostCurrency string `json:"cost_currency"`

	// EffectivePrice is the price per unit
	EffectivePrice float64 `json:"effective_price"`

	// StartTime is the start of the billing period
	StartTime time.Time `json:"start_time"`

	// EndTime is the end of the billing period
	EndTime time.Time `json:"end_time"`

	// BillingPeriod is the billing period this item belongs to (e.g., "2023-04")
	BillingPeriod string `json:"billing_period"`

	// Tags are resource tags
	Tags map[string]string `json:"tags,omitempty"`

	// TaxAmount is the tax amount
	TaxAmount float64 `json:"tax_amount"`

	// TaxRate is the tax rate
	TaxRate float64 `json:"tax_rate"`

	// Fees is a JSON-encoded []Fee
	Fees string `json:"fees"`
}
