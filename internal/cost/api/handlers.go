package api

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// CostHandler handles HTTP requests related to cost management
type CostHandler struct {
	service service.CostService
	logger  *logger.Logger
}

// NewCostHandler creates a new cost handler
func NewCostHandler(service service.CostService, log *logger.Logger) *CostHandler {
	return &CostHandler{
		service: service,
		logger:  log,
	}
}

// RegisterRoutes registers all cost management routes
func (h *CostHandler) RegisterRoutes(router fiber.Router) {
	costs := router.Group("/costs")

	// Cost data endpoints
	costs.Get("/:id", h.GetCostByID)
	costs.Post("/query", h.QueryCosts)
	costs.Get("/summary", h.GetCostSummary)

	// Import endpoints
	imports := costs.Group("/imports")
	imports.Post("/", h.ImportCostData)
	imports.Get("/:id", h.GetCostImportStatus)
	imports.Get("/", h.ListCostImports)

	// Budget endpoints
	budgets := costs.Group("/budgets")
	budgets.Post("/", h.CreateBudget)
	budgets.Put("/:id", h.UpdateBudget)
	budgets.Delete("/:id", h.DeleteBudget)
	budgets.Get("/:id", h.GetBudgetByID)
	budgets.Get("/", h.ListBudgets)

	// Anomaly endpoints
	anomalies := costs.Group("/anomalies")
	anomalies.Get("/:id", h.GetAnomalyByID)
	anomalies.Put("/:id", h.UpdateAnomaly)
	anomalies.Get("/", h.ListAnomalies)
	anomalies.Post("/detect", h.DetectAnomalies)

	// Forecast endpoints
	forecasts := costs.Group("/forecasts")
	forecasts.Post("/", h.GenerateForecast)
	forecasts.Get("/", h.GetForecast)
}

// Response formats
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

// Helper function to parse time params
func parseTimeParams(c *fiber.Ctx, startParam, endParam string, defaults bool) (time.Time, time.Time, error) {
	var startTime, endTime time.Time
	var err error

	startStr := c.Query(startParam)
	endStr := c.Query(endParam)

	if startStr != "" {
		startTime, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			return startTime, endTime, err
		}
	} else if defaults {
		// Default to last 30 days
		startTime = time.Now().UTC().Add(-30 * 24 * time.Hour)
	}

	if endStr != "" {
		endTime, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			return startTime, endTime, err
		}
	} else if defaults {
		// Default to now
		endTime = time.Now().UTC()
	}

	return startTime, endTime, nil
}

// Helper function for pagination
func getPaginationParams(c *fiber.Ctx) (int, int) {
	page := 1
	pageSize := 20

	if c.Query("page") != "" {
		page = c.QueryInt("page", 1)
		if page < 1 {
			page = 1
		}
	}

	if c.Query("page_size") != "" {
		pageSize = c.QueryInt("page_size", 20)
		if pageSize < 1 {
			pageSize = 20
		}
		if pageSize > 100 {
			pageSize = 100
		}
	}

	return page, pageSize
}

// parseProvider parses cloud provider from string
func parseProvider(providerStr string) (domain.CloudProvider, error) {
	switch providerStr {
	case "aws":
		return domain.AWS, nil
	case "azure":
		return domain.Azure, nil
	case "gcp":
		return domain.GCP, nil
	default:
		return "", service.ErrInvalidRequest
	}
}

// GetCostByID gets a cost record by ID
func (h *CostHandler) GetCostByID(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Cost ID is required",
		})
	}

	ctx := c.Context()
	cost, err := h.service.GetCostByID(ctx, id)
	if err != nil {
		if err == domain.ErrCostDataNotFound {
			return c.Status(fiber.StatusNotFound).JSON(errorResponse{
				Error:   "Not found",
				Message: "Cost record not found",
			})
		}
		h.logger.Error("Failed to get cost",
			logger.String("id", id),
			logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(cost)
}

// QueryCosts queries cost records based on filter criteria
func (h *CostHandler) QueryCosts(c *fiber.Ctx) error {
	var query domain.CostQuery
	if err := c.BodyParser(&query); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid request body",
		})
	}

	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Enforce tenant ID from context for security
	query.TenantID = tenantID

	// Set pagination defaults if not provided
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 {
		query.PageSize = 20
	}
	if query.PageSize > 100 {
		query.PageSize = 100
	}

	// Validate query
	if err := query.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid query",
			Message: err.Error(),
		})
	}

	ctx := c.Context()
	costs, total, err := h.service.QueryCosts(ctx, query)
	if err != nil {
		h.logger.Error("Failed to query costs",
			logger.String("tenant_id", query.TenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(paginatedResponse{
		Data:       costs,
		TotalCount: total,
		Page:       query.Page,
		PageSize:   query.PageSize,
	})
}

// GetCostSummary gets a summary of cost data based on filter criteria
func (h *CostHandler) GetCostSummary(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse time parameters
	startTime, endTime, err := parseTimeParams(c, "start_time", "end_time", true)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid time format. Use RFC3339 format.",
		})
	}

	// Parse granularity parameter
	granularity := domain.Daily // Default to daily
	if c.Query("granularity") != "" {
		switch c.Query("granularity") {
		case "hourly":
			granularity = domain.Hourly
		case "daily":
			granularity = domain.Daily
		case "monthly":
			granularity = domain.Monthly
		default:
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
				Error:   "Invalid request",
				Message: "Invalid granularity. Must be hourly, daily, or monthly.",
			})
		}
	}

	// Parse group_by parameter
	var groupBy []string
	groupByStr := c.Query("group_by")
	if groupByStr != "" {
		groupBy = []string{groupByStr}
	}

	// Parse provider parameter
	var providers []domain.CloudProvider
	providerStr := c.Query("provider")
	if providerStr != "" {
		provider, err := parseProvider(providerStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
				Error:   "Invalid request",
				Message: "Invalid provider. Must be aws, azure, or gcp.",
			})
		}
		providers = append(providers, provider)
	}

	// Create query
	query := domain.CostQuery{
		TenantID:    tenantID,
		Providers:   providers,
		StartTime:   startTime,
		EndTime:     endTime,
		Granularity: granularity,
		GroupBy:     groupBy,
	}

	// Parse other filter parameters
	accountID := c.Query("account_id")
	if accountID != "" {
		query.AccountIDs = []string{accountID}
	}

	service := c.Query("service")
	if service != "" {
		query.Services = []string{service}
	}

	region := c.Query("region")
	if region != "" {
		query.Regions = []string{region}
	}

	ctx := c.Context()
	summary, err := h.service.GetCostSummary(ctx, query)
	if err != nil {
		h.logger.Error("Failed to get cost summary",
			logger.String("tenant_id", query.TenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(summary)
}

// ImportCostData initiates a cost data import from a cloud provider
func (h *CostHandler) ImportCostData(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse request body
	type importRequest struct {
		Provider  string    `json:"provider"`
		AccountID string    `json:"account_id"`
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
	}

	var req importRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid request body",
		})
	}

	// Validate provider
	provider, err := parseProvider(req.Provider)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid provider. Must be aws, azure, or gcp.",
		})
	}

	// Validate account ID
	if req.AccountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Account ID is required",
		})
	}

	// Validate time range
	if req.StartTime.After(req.EndTime) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Start time must be before end time",
		})
	}

	ctx := c.Context()
	costImport, err := h.service.ImportCostData(ctx, tenantID, provider, req.AccountID, req.StartTime, req.EndTime)
	if err != nil {
		h.logger.Error("Failed to import cost data",
			logger.String("tenant_id", tenantID),
			logger.String("provider", req.Provider),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusAccepted).JSON(costImport)
}

// GetCostImportStatus gets the status of a cost data import
func (h *CostHandler) GetCostImportStatus(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Import ID is required",
		})
	}

	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	ctx := c.Context()
	costImport, err := h.service.GetCostImportStatus(ctx, id)
	if err != nil {
		if err == domain.ErrCostDataNotFound {
			return c.Status(fiber.StatusNotFound).JSON(errorResponse{
				Error:   "Not found",
				Message: "Cost import not found",
			})
		}
		h.logger.Error("Failed to get cost import status",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	// Security check: ensure the import belongs to the requesting tenant
	if costImport.TenantID != tenantID {
		return c.Status(fiber.StatusForbidden).JSON(errorResponse{
			Error:   "Forbidden",
			Message: "You don't have permission to access this resource",
		})
	}

	return c.Status(fiber.StatusOK).JSON(costImport)
}

// ListCostImports lists cost import operations for a tenant
func (h *CostHandler) ListCostImports(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse time parameters
	startTime, endTime, err := parseTimeParams(c, "start_time", "end_time", true)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid time format. Use RFC3339 format.",
		})
	}

	// Parse provider parameter
	var provider domain.CloudProvider
	providerStr := c.Query("provider")
	if providerStr != "" {
		provider, err = parseProvider(providerStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
				Error:   "Invalid request",
				Message: "Invalid provider. Must be aws, azure, or gcp.",
			})
		}
	}

	// Get pagination parameters
	page, pageSize := getPaginationParams(c)

	ctx := c.Context()
	imports, total, err := h.service.ListCostImports(ctx, tenantID, provider, startTime, endTime, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list cost imports",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(paginatedResponse{
		Data:       imports,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	})
}

// CreateBudget creates a new budget
func (h *CostHandler) CreateBudget(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse request body
	var budget domain.Budget
	if err := c.BodyParser(&budget); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid request body",
		})
	}

	// Enforce tenant ID from context for security
	budget.TenantID = tenantID

	// Validate required fields
	if budget.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Budget name is required",
		})
	}

	if budget.Amount <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Budget amount must be greater than zero",
		})
	}

	if budget.Currency == "" {
		budget.Currency = "USD" // Default to USD
	}

	if budget.Period == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Budget period is required",
		})
	}

	// Create the budget
	ctx := c.Context()
	createdBudget, err := h.service.CreateBudget(ctx, &budget)
	if err != nil {
		h.logger.Error("Failed to create budget",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		if err == service.ErrInvalidRequest {
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
				Error:   "Invalid request",
				Message: "Invalid budget data",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(createdBudget)
}

// UpdateBudget updates an existing budget
func (h *CostHandler) UpdateBudget(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Budget ID is required",
		})
	}

	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse request body
	var budget domain.Budget
	if err := c.BodyParser(&budget); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid request body",
		})
	}

	// Set ID and tenant ID from request
	budget.ID = id
	budget.TenantID = tenantID

	// Update the budget
	ctx := c.Context()
	updatedBudget, err := h.service.UpdateBudget(ctx, &budget)
	if err != nil {
		h.logger.Error("Failed to update budget",
			logger.String("id", id),
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		if err == domain.ErrCostDataNotFound {
			return c.Status(fiber.StatusNotFound).JSON(errorResponse{
				Error:   "Not found",
				Message: "Budget not found",
			})
		}
		if err == service.ErrPermissionDenied {
			return c.Status(fiber.StatusForbidden).JSON(errorResponse{
				Error:   "Forbidden",
				Message: "You don't have permission to update this budget",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(updatedBudget)
}

// DeleteBudget deletes a budget
func (h *CostHandler) DeleteBudget(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Budget ID is required",
		})
	}

	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// First get the budget to verify ownership
	ctx := c.Context()
	budget, err := h.service.GetBudgetByID(ctx, id)
	if err != nil {
		if err == domain.ErrCostDataNotFound {
			return c.Status(fiber.StatusNotFound).JSON(errorResponse{
				Error:   "Not found",
				Message: "Budget not found",
			})
		}
		h.logger.Error("Failed to get budget for deletion",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	// Security check: ensure the budget belongs to the requesting tenant
	if budget.TenantID != tenantID {
		return c.Status(fiber.StatusForbidden).JSON(errorResponse{
			Error:   "Forbidden",
			Message: "You don't have permission to delete this budget",
		})
	}

	// Delete the budget
	if err := h.service.DeleteBudget(ctx, id); err != nil {
		h.logger.Error("Failed to delete budget",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusNoContent).Send(nil)
}

// GetBudgetByID gets a budget by ID
func (h *CostHandler) GetBudgetByID(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Budget ID is required",
		})
	}

	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	ctx := c.Context()
	budget, err := h.service.GetBudgetByID(ctx, id)
	if err != nil {
		if err == domain.ErrCostDataNotFound {
			return c.Status(fiber.StatusNotFound).JSON(errorResponse{
				Error:   "Not found",
				Message: "Budget not found",
			})
		}
		h.logger.Error("Failed to get budget",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	// Security check: ensure the budget belongs to the requesting tenant
	if budget.TenantID != tenantID {
		return c.Status(fiber.StatusForbidden).JSON(errorResponse{
			Error:   "Forbidden",
			Message: "You don't have permission to access this budget",
		})
	}

	return c.Status(fiber.StatusOK).JSON(budget)
}

// ListBudgets lists budgets for a tenant
func (h *CostHandler) ListBudgets(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse provider parameter
	var provider domain.CloudProvider
	providerStr := c.Query("provider")
	if providerStr != "" {
		var err error
		provider, err = parseProvider(providerStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
				Error:   "Invalid request",
				Message: "Invalid provider. Must be aws, azure, or gcp.",
			})
		}
	}

	// Parse active parameter
	active := true // Default to active budgets
	if c.Query("active") != "" {
		if c.Query("active") == "false" {
			active = false
		}
	}

	// Get pagination parameters
	page, pageSize := getPaginationParams(c)

	ctx := c.Context()
	budgets, total, err := h.service.ListBudgets(ctx, tenantID, provider, active, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list budgets",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(paginatedResponse{
		Data:       budgets,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	})
}

// GetAnomalyByID gets an anomaly by ID
func (h *CostHandler) GetAnomalyByID(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Anomaly ID is required",
		})
	}

	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	ctx := c.Context()
	anomaly, err := h.service.GetAnomalyByID(ctx, id)
	if err != nil {
		if err == domain.ErrCostDataNotFound {
			return c.Status(fiber.StatusNotFound).JSON(errorResponse{
				Error:   "Not found",
				Message: "Anomaly not found",
			})
		}
		h.logger.Error("Failed to get anomaly",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	// Security check: ensure the anomaly belongs to the requesting tenant
	if anomaly.TenantID != tenantID {
		return c.Status(fiber.StatusForbidden).JSON(errorResponse{
			Error:   "Forbidden",
			Message: "You don't have permission to access this anomaly",
		})
	}

	return c.Status(fiber.StatusOK).JSON(anomaly)
}

// UpdateAnomaly updates an anomaly (e.g., to acknowledge or resolve it)
func (h *CostHandler) UpdateAnomaly(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Anomaly ID is required",
		})
	}

	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse request body
	type anomalyUpdate struct {
		Status        string `json:"status"`
		RootCause     string `json:"root_cause,omitempty"`
		FalsePositive bool   `json:"false_positive,omitempty"`
	}

	var update anomalyUpdate
	if err := c.BodyParser(&update); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid request body",
		})
	}

	// Validate status
	if update.Status != "" && update.Status != "open" && update.Status != "acknowledged" &&
		update.Status != "resolved" && update.Status != "false_positive" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid status. Must be open, acknowledged, resolved, or false_positive.",
		})
	}

	// Get the existing anomaly
	ctx := c.Context()
	anomaly, err := h.service.GetAnomalyByID(ctx, id)
	if err != nil {
		if err == domain.ErrCostDataNotFound {
			return c.Status(fiber.StatusNotFound).JSON(errorResponse{
				Error:   "Not found",
				Message: "Anomaly not found",
			})
		}
		h.logger.Error("Failed to get anomaly for update",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	// Security check: ensure the anomaly belongs to the requesting tenant
	if anomaly.TenantID != tenantID {
		return c.Status(fiber.StatusForbidden).JSON(errorResponse{
			Error:   "Forbidden",
			Message: "You don't have permission to update this anomaly",
		})
	}

	// Update the anomaly fields
	if update.Status != "" {
		anomaly.Status = update.Status
	}

	if update.RootCause != "" {
		anomaly.RootCause = update.RootCause
	}

	if update.FalsePositive {
		anomaly.Status = "false_positive"
	}

	// Update the anomaly
	updatedAnomaly, err := h.service.UpdateAnomaly(ctx, anomaly)
	if err != nil {
		h.logger.Error("Failed to update anomaly",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(updatedAnomaly)
}

// ListAnomalies lists anomalies for a tenant
func (h *CostHandler) ListAnomalies(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse time parameters
	startTime, endTime, err := parseTimeParams(c, "start_time", "end_time", true)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid time format. Use RFC3339 format.",
		})
	}

	// Parse provider parameter
	var provider domain.CloudProvider
	providerStr := c.Query("provider")
	if providerStr != "" {
		provider, err = parseProvider(providerStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
				Error:   "Invalid request",
				Message: "Invalid provider. Must be aws, azure, or gcp.",
			})
		}
	}

	// Parse status parameter
	status := c.Query("status") // Can be empty to get all

	// Get pagination parameters
	page, pageSize := getPaginationParams(c)

	ctx := c.Context()
	anomalies, total, err := h.service.ListAnomalies(ctx, tenantID, provider, startTime, endTime, status, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list anomalies",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(paginatedResponse{
		Data:       anomalies,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	})
}

// DetectAnomalies runs anomaly detection for a specific time range
func (h *CostHandler) DetectAnomalies(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse request body
	type detectRequest struct {
		Provider  string    `json:"provider"`
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
	}

	var req detectRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid request body",
		})
	}

	// Validate provider
	provider, err := parseProvider(req.Provider)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid provider. Must be aws, azure, or gcp.",
		})
	}

	// Validate time range
	if req.StartTime.After(req.EndTime) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Start time must be before end time",
		})
	}

	ctx := c.Context()
	anomalyCount, err := h.service.DetectAnomalies(ctx, tenantID, provider, req.StartTime, req.EndTime)
	if err != nil {
		h.logger.Error("Failed to detect anomalies",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"anomalies_detected": anomalyCount,
		"provider":           provider,
		"start_time":         req.StartTime,
		"end_time":           req.EndTime,
	})
}

// GenerateForecast generates a cost forecast
func (h *CostHandler) GenerateForecast(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse request body
	type forecastRequest struct {
		Provider  string    `json:"provider"`
		AccountID string    `json:"account_id"`
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
	}

	var req forecastRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid request body",
		})
	}

	// Validate provider
	provider, err := parseProvider(req.Provider)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid provider. Must be aws, azure, or gcp.",
		})
	}

	// Validate account ID
	if req.AccountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Account ID is required",
		})
	}

	// Validate time range
	if req.StartTime.After(req.EndTime) {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Start time must be before end time",
		})
	}

	ctx := c.Context()
	forecast, err := h.service.GenerateForecast(ctx, tenantID, provider, req.AccountID, req.StartTime, req.EndTime)
	if err != nil {
		h.logger.Error("Failed to generate forecast",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(forecast)
}

// GetForecast gets a cost forecast
func (h *CostHandler) GetForecast(c *fiber.Ctx) error {
	// Get tenant ID from request context (set by auth middleware)
	tenantID := c.Locals("tenant_id").(string)
	if tenantID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(errorResponse{
			Error:   "Unauthorized",
			Message: "Missing tenant ID",
		})
	}

	// Parse provider parameter
	providerStr := c.Query("provider")
	if providerStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Provider is required",
		})
	}

	provider, err := parseProvider(providerStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid provider. Must be aws, azure, or gcp.",
		})
	}

	// Parse account ID parameter
	accountID := c.Query("account_id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Account ID is required",
		})
	}

	// Parse time parameters
	startTime, endTime, err := parseTimeParams(c, "start_time", "end_time", true)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errorResponse{
			Error:   "Invalid request",
			Message: "Invalid time format. Use RFC3339 format.",
		})
	}

	ctx := c.Context()
	forecast, err := h.service.GetForecast(ctx, tenantID, provider, accountID, startTime, endTime)
	if err != nil {
		h.logger.Error("Failed to get forecast",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err),
		)
		return c.Status(fiber.StatusInternalServerError).JSON(errorResponse{
			Error: "Internal server error",
		})
	}

	return c.Status(fiber.StatusOK).JSON(forecast)
}
