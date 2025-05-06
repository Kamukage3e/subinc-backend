package api

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

const (
	// TenantIDHeader is the header containing the tenant ID
	TenantIDHeader = "X-Tenant-ID"

	// DefaultErrorMessage is the default error message
	DefaultErrorMessage = "An unexpected error occurred"
)

// CloudHandler handles API requests for cloud provider integrations
type CloudHandler struct {
	cloudProviderService service.CloudProviderService
	logger               *logger.Logger
}

// Request/Response types

// CreateIntegrationRequest represents a request to create a new integration
type CreateIntegrationRequest struct {
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
}

// UpdateIntegrationRequest represents a request to update an integration
type UpdateIntegrationRequest struct {
	Credentials map[string]string `json:"credentials"`
}

// IntegrationResponse represents a cloud provider integration response
type IntegrationResponse struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Provider        string     `json:"provider"`
	DefaultAccount  string     `json:"default_account,omitempty"`
	AccountCount    int        `json:"account_count"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastValidatedAt *time.Time `json:"last_validated_at,omitempty"`
	IsValid         bool       `json:"is_valid"`
}

// IntegrationsResponse represents a list of cloud provider integrations
type IntegrationsResponse struct {
	Integrations []IntegrationResponse `json:"integrations"`
	Count        int                   `json:"count"`
}

// ProviderResponse represents a cloud provider response
type ProviderResponse struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	Features    []string `json:"features,omitempty"`
	DocsURL     string   `json:"docs_url,omitempty"`
}

// ProviderInfoResponse represents detailed information about a cloud provider
type ProviderInfoResponse struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	APIVersion  string   `json:"api_version,omitempty"`
	Features    []string `json:"features,omitempty"`
	DocsURL     string   `json:"docs_url,omitempty"`
}

// ProvidersResponse represents a list of cloud providers
type ProvidersResponse struct {
	Providers []ProviderResponse `json:"providers"`
}

// ValidationResponse represents the result of a validation check
type ValidationResponse struct {
	Valid       bool       `json:"valid"`
	LastChecked *time.Time `json:"last_checked,omitempty"`
	Message     string     `json:"message"`
}

// AccountResponse represents a cloud account response
type AccountResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Status    string            `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
	Owner     string            `json:"owner,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	IsDefault bool              `json:"is_default"`
}

// AccountsResponse represents a list of cloud accounts
type AccountsResponse struct {
	Accounts []AccountResponse `json:"accounts"`
	Count    int               `json:"count"`
}

// SetDefaultAccountRequest represents a request to set the default account
type SetDefaultAccountRequest struct {
	AccountID string `json:"account_id"`
}

// ImportCostDataRequest represents a request to import cost data
type ImportCostDataRequest struct {
	Provider  string    `json:"provider"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// ImportResponse represents the result of a cost import request
type ImportResponse struct {
	ImportID  string    `json:"import_id"`
	Status    string    `json:"status"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Provider  string    `json:"provider"`
	Message   string    `json:"message"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}


type BillingHandler struct {
	service                  service.BillingService
	couponService            service.CouponService
	creditService            service.CreditService
	refundService            service.RefundService
	paymentMethodService     service.PaymentMethodService
	subscriptionService      service.SubscriptionService
	webhookEventService      service.WebhookEventService
	invoiceAdjustmentService service.InvoiceAdjustmentService
}

// CouponInput for RORO pattern
// Used by API handler for Coupon endpoints
type CouponInput struct {
	Coupon *domain.Coupon
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

// BaseHandler provides common functionality for all handlers
type BaseHandler struct {
	logger *logger.Logger
}

type AnomalyHandler struct {
	anomalyService service.AnomalyDetectionService
	logger         *logger.Logger
}

// CostHandler handles HTTP requests related to cost management
type CostHandler struct {
	service service.CostService
	logger  *logger.Logger
} 

type OptimizationHandler struct {
	service *service.OptimizationService
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

type paginatedResponse struct {
	Data       interface{} `json:"data"`
	TotalCount int         `json:"total_count"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
}

// Router sets up all API routes
type Router struct {
	router               fiber.Router
	costService          service.CostService
	cloudProviderService service.CloudProviderService
	billingService       service.BillingService
	couponService        service.CouponService
	optimizationService  *service.OptimizationService
	logger               *logger.Logger
	secretsManager       secrets.SecretsManager
	jwtSecretName        string
}