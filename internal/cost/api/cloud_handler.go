package api

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// NewCloudHandler creates a new cloud handler
func NewCloudHandler(cloudProviderService service.CloudProviderService, log *logger.Logger) *CloudHandler {
	if log == nil {
		log = logger.NewNoop()
	}

	return &CloudHandler{
		cloudProviderService: cloudProviderService,
		logger:               log,
	}
}

// ListProviders lists all supported cloud providers
// @Summary List all supported cloud providers
// @Description Get a list of all supported cloud providers
// @Tags Cloud
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} ProvidersResponse
// @Router /api/cost/cloud/providers [get]
func (h *CloudHandler) ListProviders(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get a list of supported providers
	providers := h.cloudProviderService.GetSupportedProviders(c.Context())

	response := ProvidersResponse{
		Providers: make([]ProviderResponse, len(providers)),
	}

	// Get info for each provider
	for i, provider := range providers {
		info, err := h.cloudProviderService.GetProviderInfo(c.Context(), provider)
		if err != nil {
			h.logger.Error("Failed to get provider info",
				logger.String("tenant_id", tenantID),
				logger.String("provider", string(provider)),
				logger.ErrorField(err))

			// Use basic info if details not available
			response.Providers[i] = ProviderResponse{
				ID:          string(provider),
				DisplayName: getProviderDisplayName(provider),
				Description: "Cloud provider details not available",
			}
			continue
		}

		response.Providers[i] = ProviderResponse{
			ID:          string(info.Provider),
			DisplayName: info.DisplayName,
			Description: info.Description,
			Features:    info.Features,
			DocsURL:     info.DocsURL,
		}
	}

	return c.JSON(response)
}

// GetProviderInfo gets information about a specific cloud provider
// @Summary Get provider info
// @Description Get detailed information about a specific cloud provider
// @Tags Cloud
// @Accept json
// @Produce json
// @Param provider path string true "Provider ID (aws, azure, gcp)"
// @Security ApiKeyAuth
// @Success 200 {object} ProviderInfoResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/cost/cloud/providers/{provider} [get]
func (h *CloudHandler) GetProviderInfo(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get provider from path
	providerStr := c.Params("provider")
	provider := domain.CloudProvider(providerStr)

	// Get provider info
	info, err := h.cloudProviderService.GetProviderInfo(c.Context(), provider)
	if err != nil {
		h.logger.Error("Failed to get provider info",
			logger.String("tenant_id", tenantID),
			logger.String("provider", providerStr),
			logger.ErrorField(err))
		return newErrorResponse(c, fiber.StatusBadRequest, "Invalid cloud provider")
	}

	// Create response
	response := ProviderInfoResponse{
		ID:          string(info.Provider),
		DisplayName: info.DisplayName,
		Description: info.Description,
		APIVersion:  info.APIVersion,
		Features:    info.Features,
		DocsURL:     info.DocsURL,
	}

	return c.JSON(response)
}

// CreateIntegration adds a new cloud provider integration
// @Summary Create integration
// @Description Add a new cloud provider integration
// @Tags Cloud
// @Accept json
// @Produce json
// @Param input body CreateIntegrationRequest true "Integration details"
// @Security ApiKeyAuth
// @Success 201 {object} IntegrationResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/cost/cloud/integrations [post]
func (h *CloudHandler) CreateIntegration(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Parse request body
	var req CreateIntegrationRequest
	if err := c.BodyParser(&req); err != nil {
		return newErrorResponse(c, fiber.StatusBadRequest, "Invalid request body")
	}

	// Validate request
	if req.Name == "" || req.Provider == "" || len(req.Credentials) == 0 {
		return newErrorResponse(c, fiber.StatusBadRequest, "Name, provider, and credentials are required")
	}

	// Create integration
	credential, err := h.cloudProviderService.AddCloudIntegration(
		c.Context(),
		tenantID,
		domain.CloudProvider(req.Provider),
		req.Name,
		req.Credentials,
	)
	if err != nil {
		h.logger.Error("Failed to create integration",
			logger.String("tenant_id", tenantID),
			logger.String("provider", req.Provider),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Create response
	response := mapCredentialToResponse(credential)

	return c.Status(fiber.StatusCreated).JSON(response)
}

// ListIntegrations lists all cloud provider integrations for a tenant
// @Summary List integrations
// @Description List all cloud provider integrations for a tenant
// @Tags Cloud
// @Accept json
// @Produce json
// @Param provider query string false "Filter by provider (aws, azure, gcp)"
// @Security ApiKeyAuth
// @Success 200 {object} IntegrationsResponse
// @Router /api/cost/cloud/integrations [get]
func (h *CloudHandler) ListIntegrations(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get provider filter from query
	var providerFilter *domain.CloudProvider
	if provider := c.Query("provider"); provider != "" {
		p := domain.CloudProvider(provider)
		providerFilter = &p
	}

	// List integrations
	credentials, err := h.cloudProviderService.ListCloudIntegrations(c.Context(), tenantID, providerFilter)
	if err != nil {
		h.logger.Error("Failed to list integrations",
			logger.String("tenant_id", tenantID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Create response
	integrations := make([]IntegrationResponse, len(credentials))
	for i, cred := range credentials {
		integrations[i] = mapCredentialToResponse(cred)
	}

	// Encode all IDs
	for i := range integrations {
		integrations[i].ID = encodeID(integrations[i].ID)
	}

	response := IntegrationsResponse{
		Integrations: integrations,
		Count:        len(integrations),
	}

	return c.JSON(response)
}

// GetIntegration gets a specific cloud provider integration
// @Summary Get integration
// @Description Get a specific cloud provider integration by ID
// @Tags Cloud
// @Accept json
// @Produce json
// @Param id path string true "Integration ID"
// @Security ApiKeyAuth
// @Success 200 {object} IntegrationResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/cost/cloud/integrations/{id} [get]
func (h *CloudHandler) GetIntegration(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get integration ID from path
	integrationID := c.Params("id")
	if integrationID == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Integration ID is required")
	}

	// Get integration
	credential, err := h.cloudProviderService.GetCloudIntegration(c.Context(), tenantID, integrationID)
	if err != nil {
		h.logger.Error("Failed to get integration",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Create response
	response := mapCredentialToResponse(credential)

	// Encode ID
	response.ID = encodeID(response.ID)

	return c.JSON(response)
}

// UpdateIntegration updates an existing cloud provider integration
// @Summary Update integration
// @Description Update an existing cloud provider integration
// @Tags Cloud
// @Accept json
// @Produce json
// @Param id path string true "Integration ID"
// @Param input body UpdateIntegrationRequest true "Integration details"
// @Security ApiKeyAuth
// @Success 200 {object} IntegrationResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/cost/cloud/integrations/{id} [put]
func (h *CloudHandler) UpdateIntegration(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get integration ID from path
	integrationID := c.Params("id")
	if integrationID == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Integration ID is required")
	}

	// Parse request body
	var req UpdateIntegrationRequest
	if err := c.BodyParser(&req); err != nil {
		return newErrorResponse(c, fiber.StatusBadRequest, "Invalid request body")
	}

	// Validate request
	if len(req.Credentials) == 0 {
		return newErrorResponse(c, fiber.StatusBadRequest, "Credentials are required")
	}

	// Update integration
	credential, err := h.cloudProviderService.UpdateCloudIntegration(
		c.Context(),
		tenantID,
		integrationID,
		req.Credentials,
	)
	if err != nil {
		h.logger.Error("Failed to update integration",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Create response
	response := mapCredentialToResponse(credential)

	// Encode ID
	response.ID = encodeID(response.ID)

	return c.JSON(response)
}

// DeleteIntegration deletes a cloud provider integration
// @Summary Delete integration
// @Description Delete a cloud provider integration
// @Tags Cloud
// @Accept json
// @Produce json
// @Param id path string true "Integration ID"
// @Security ApiKeyAuth
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Router /api/cost/cloud/integrations/{id} [delete]
func (h *CloudHandler) DeleteIntegration(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get integration ID from path
	integrationID := c.Params("id")
	if integrationID == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Integration ID is required")
	}

	// Delete integration
	err = h.cloudProviderService.DeleteCloudIntegration(c.Context(), tenantID, integrationID)
	if err != nil {
		h.logger.Error("Failed to delete integration",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ValidateIntegration validates a cloud provider integration
// @Summary Validate integration
// @Description Validate a cloud provider integration
// @Tags Cloud
// @Accept json
// @Produce json
// @Param id path string true "Integration ID"
// @Security ApiKeyAuth
// @Success 200 {object} ValidationResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/cost/cloud/integrations/{id}/validate [post]
func (h *CloudHandler) ValidateIntegration(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get integration ID from path
	integrationID := c.Params("id")
	if integrationID == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Integration ID is required")
	}

	// Validate integration
	credential, err := h.cloudProviderService.ValidateCloudIntegration(c.Context(), tenantID, integrationID)
	if err != nil {
		h.logger.Error("Failed to validate integration",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Create response
	response := ValidationResponse{
		Valid:       credential.IsValid,
		LastChecked: credential.LastValidatedAt,
		Message:     getValidationMessage(credential.IsValid),
	}

	return c.JSON(response)
}

// ListAccounts lists cloud accounts for a tenant's integration
// @Summary List cloud accounts
// @Description List cloud accounts for a tenant's integration
// @Tags Cloud
// @Accept json
// @Produce json
// @Param id path string true "Integration ID"
// @Security ApiKeyAuth
// @Success 200 {object} AccountsResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/cost/cloud/integrations/{id}/accounts [get]
func (h *CloudHandler) ListAccounts(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get integration ID from path
	integrationID := c.Params("id")
	if integrationID == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Integration ID is required")
	}

	// Get cloud accounts
	accounts, err := h.cloudProviderService.ListCloudAccounts(c.Context(), tenantID, integrationID)
	if err != nil {
		h.logger.Error("Failed to list accounts",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Create response
	accountResponses := make([]AccountResponse, len(accounts))
	for i, account := range accounts {
		accountResponses[i] = AccountResponse{
			ID:        account.ID,
			Name:      account.Name,
			Type:      account.Type,
			Status:    account.Status,
			CreatedAt: account.CreatedAt,
			Owner:     account.Owner,
			Tags:      account.Tags,
		}
	}

	// Get the integration to check the default account
	credential, err := h.cloudProviderService.GetCloudIntegration(c.Context(), tenantID, integrationID)
	if err != nil {
		h.logger.Warn("Failed to get integration for default account check",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		// Continue without default account info
	} else {
		// Mark default account
		for i, acct := range accountResponses {
			if acct.ID == credential.DefaultAccount {
				accountResponses[i].IsDefault = true
			}
		}
	}

	// Encode all IDs
	for i := range accountResponses {
		accountResponses[i].ID = encodeID(accountResponses[i].ID)
	}

	response := AccountsResponse{
		Accounts: accountResponses,
		Count:    len(accountResponses),
	}

	return c.JSON(response)
}

// SetDefaultAccount sets the default account for a cloud integration
// @Summary Set default account
// @Description Set the default account for a cloud integration
// @Tags Cloud
// @Accept json
// @Produce json
// @Param id path string true "Integration ID"
// @Param input body SetDefaultAccountRequest true "Default account details"
// @Security ApiKeyAuth
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/cost/cloud/integrations/{id}/accounts/default [put]
func (h *CloudHandler) SetDefaultAccount(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Get integration ID from path
	integrationID := c.Params("id")
	if integrationID == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Integration ID is required")
	}

	// Parse request body
	var req SetDefaultAccountRequest
	if err := c.BodyParser(&req); err != nil {
		return newErrorResponse(c, fiber.StatusBadRequest, "Invalid request body")
	}

	// Validate request
	if req.AccountID == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Account ID is required")
	}

	// Get the integration
	integration, err := h.cloudProviderService.GetCloudIntegration(c.Context(), tenantID, integrationID)
	if err != nil {
		h.logger.Error("Failed to get integration for setting default account",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Update default account
	integration.DefaultAccount = req.AccountID
	integration.UpdatedAt = time.Now().UTC()

	// Save changes
	_, err = h.cloudProviderService.UpdateCloudIntegration(
		c.Context(),
		tenantID,
		integrationID,
		integration.Credentials,
	)
	if err != nil {
		h.logger.Error("Failed to set default account",
			logger.String("tenant_id", tenantID),
			logger.String("integration_id", integrationID),
			logger.String("account_id", req.AccountID),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	return c.JSON(SuccessResponse{
		Success: true,
		Message: "Default account updated successfully",
	})
}

// ImportCostData initiates a cost data import
// @Summary Import cost data
// @Description Import cost data from a cloud provider
// @Tags Cloud
// @Accept json
// @Produce json
// @Param input body ImportCostDataRequest true "Import details"
// @Security ApiKeyAuth
// @Success 202 {object} ImportResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/cost/cloud/import [post]
func (h *CloudHandler) ImportCostData(c *fiber.Ctx) error {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return err
	}

	// Parse request body
	var req ImportCostDataRequest
	if err := c.BodyParser(&req); err != nil {
		return newErrorResponse(c, fiber.StatusBadRequest, "Invalid request body")
	}

	// Validate request
	if req.Provider == "" {
		return newErrorResponse(c, fiber.StatusBadRequest, "Provider is required")
	}

	// Validate dates
	startDate := req.StartDate
	endDate := req.EndDate

	if startDate.IsZero() {
		// Default to start of current month
		now := time.Now().UTC()
		startDate = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}

	if endDate.IsZero() {
		// Default to now
		endDate = time.Now().UTC()
	}

	// Start import
	costImport, err := h.cloudProviderService.ImportCostData(
		c.Context(),
		tenantID,
		domain.CloudProvider(req.Provider),
		startDate,
		endDate,
	)
	if err != nil {
		h.logger.Error("Failed to import cost data",
			logger.String("tenant_id", tenantID),
			logger.String("provider", req.Provider),
			logger.Time("start_date", startDate),
			logger.Time("end_date", endDate),
			logger.ErrorField(err))
		return handleServiceError(c, err)
	}

	// Create response
	response := ImportResponse{
		ImportID:  costImport.ID,
		Status:    costImport.Status,
		StartDate: costImport.StartTime,
		EndDate:   costImport.EndTime,
		Provider:  string(costImport.Provider),
		Message:   "Cost import started successfully",
	}

	return c.Status(fiber.StatusAccepted).JSON(response)
}

// Helper functions

// mapCredentialToResponse maps a credential to a response object
func mapCredentialToResponse(cred *repository.CloudCredential) IntegrationResponse {
	return IntegrationResponse{
		ID:              cred.ID,
		Name:            cred.Name,
		Provider:        string(cred.Provider),
		DefaultAccount:  cred.DefaultAccount,
		AccountCount:    len(cred.AccountList),
		CreatedAt:       cred.CreatedAt,
		UpdatedAt:       cred.UpdatedAt,
		LastValidatedAt: cred.LastValidatedAt,
		IsValid:         cred.IsValid,
	}
}

// getValidationMessage returns a message based on validation result
func getValidationMessage(isValid bool) string {
	if isValid {
		return "Credentials are valid"
	}
	return "Credentials are invalid"
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

// handleServiceError handles service errors and returns appropriate HTTP responses
func handleServiceError(c *fiber.Ctx, err error) error {
	switch err {
	case service.ErrInvalidCloudProvider:
		return newErrorResponse(c, fiber.StatusBadRequest, "Invalid cloud provider")
	case service.ErrIntegrationNotFound:
		return newErrorResponse(c, fiber.StatusNotFound, "Cloud integration not found")
	case service.ErrDuplicateIntegration:
		return newErrorResponse(c, fiber.StatusConflict, "A cloud integration with this name already exists")
	case repository.ErrPermissionDenied:
		return newErrorResponse(c, fiber.StatusForbidden, "Permission denied")
	default:
		return newErrorResponse(c, fiber.StatusInternalServerError, "An error occurred")
	}
}
