package account

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// setTenantContextForOperations ensures tenant_id is set in context for downstream operations
func setTenantContextForOperations(c *fiber.Ctx) context.Context {
	ctx := c.Context()
	tenantID := c.Get("X-Tenant-ID")

	// If we have a tenant ID in the header, add it to the context
	if tenantID != "" {
		ctx.SetUserValue("tenant_id", tenantID)
	}

	// Check if tenant ID is in locals (set by TenantMiddleware)
	if localTenantID, ok := c.Locals("tenant_id").(string); ok && localTenantID != "" {
		ctx.SetUserValue("tenant_id", localTenantID)
	}

	return ctx
}

func (h *AccountHandler) CreateAccount(c *fiber.Ctx) error {
	accountType := c.Query("type", "project")
	ctx := setTenantContextForOperations(c)
	var input interface{}
	switch accountType {
	case "user":
		input = &UserBillingAccount{}
	case "organization":
		input = &OrganizationBillingAccount{}
	default:
		input = &ProjectBillingAccount{}
	}
	if err := c.BodyParser(input); err != nil {
		logger.LogError("CreateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	// Extract and validate the tenantID
	var tenantID string
	var tenantCreate bool
	var tenantType string

	// Parse additional tenant information
	var tenantInfo struct {
		CreateTenant bool   `json:"create_tenant"`
		TenantName   string `json:"tenant_name"`
		TenantType   string `json:"tenant_type"`
	}
	if err := c.BodyParser(&tenantInfo); err == nil {
		tenantCreate = tenantInfo.CreateTenant
		tenantType = tenantInfo.TenantType
		if tenantType == "" {
			tenantType = string(TenantTypeShared) // Default is shared tenant
		}
	}

	// Get existing tenant ID from request or context
	tenantID = c.Get("X-Tenant-ID")
	if tenantID == "" {
		// If not in header, check context (could be set by middleware) or locals
		if v := ctx.Value("tenant_id"); v != nil {
			if tid, ok := v.(string); ok && tid != "" {
				tenantID = tid
			}
		}

		// Check locals as well (set by middleware)
		if localTenantID, ok := c.Locals("tenant_id").(string); ok && localTenantID != "" {
			tenantID = localTenantID
		}
	}

	// Check if we need to create a new tenant
	if tenantCreate {
		// Create a new tenant if specified
		newTenant := &tenant_management.Tenant{
			ID:        uuid.NewString(),
			Name:      tenantInfo.TenantName,
			Status:    tenant_management.TenantStatusActive,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}

		// Default tenant name if not provided
		if newTenant.Name == "" {
			switch v := input.(type) {
			case *UserBillingAccount:
				newTenant.Name = "Tenant for " + v.Email
			case *OrganizationBillingAccount:
				newTenant.Name = "Tenant for " + v.Email
			case *ProjectBillingAccount:
				newTenant.Name = "Tenant for " + v.Email
			}
		}

		// Store tenant type in settings
		settings := map[string]interface{}{
			"tenant_type": tenantType,
			"created_by":  "billing-management",
			"created_at":  time.Now().UTC().Format(time.RFC3339),
		}
		settingsJSON, _ := json.Marshal(settings)
		newTenant.Settings = string(settingsJSON)

		// Create tenant
		if err := h.TenantService.CreateTenant(ctx, newTenant); err != nil {
			logger.LogError("CreateAccount: failed to create tenant",
				logger.ErrorField(err),
				logger.String("tenant_name", newTenant.Name))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create tenant",
				"code":  "TENANT_CREATE_FAILED",
			})
		}

		// Use the new tenant ID
		tenantID = newTenant.ID

		// Log tenant creation
		logger.LogInfo("CreateAccount: created new tenant",
			logger.String("tenant_id", tenantID),
			logger.String("tenant_name", newTenant.Name),
			logger.String("tenant_type", tenantType))
	}

	// Return error if no tenant ID
	if tenantID == "" {
		logger.LogError("CreateAccount: no tenant ID provided")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing tenant ID. Either provide X-Tenant-ID header or set create_tenant=true",
			"code":  "TENANT_REQUIRED",
		})
	}

	now := time.Now().UTC()
	switch v := input.(type) {
	case *UserBillingAccount:
		v.ID = commonutil.GenerateUUID()
		v.TenantID = tenantID
		v.CreatedAt = now
		v.UpdatedAt = now
	case *OrganizationBillingAccount:
		v.ID = commonutil.GenerateUUID()
		v.TenantID = tenantID
		v.CreatedAt = now
		v.UpdatedAt = now
	case *ProjectBillingAccount:
		v.ID = commonutil.GenerateUUID()
		v.TenantID = tenantID
		v.CreatedAt = now
		v.UpdatedAt = now
	}

	if v, ok := input.(interface{ Validate() *Error }); ok {
		if err := v.Validate(); err != nil {
			logger.LogError("CreateAccount: validation failed", logger.ErrorField(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
				"code":  "VALIDATION_ERROR",
				"field": err.Field,
			})
		}
	}

	account, err := h.BillingAccountService.Create(ctx, BillingAccountType(accountType), input)
	if err != nil {
		logger.LogError("CreateAccount: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create billing account",
			"code":  "ACCOUNT_CREATE_FAILED",
		})
	}

	if h.NotificationService != nil && account != nil {
		go func(acct interface{}) {
			var email, id, status string
			var createdAt any
			switch a := acct.(type) {
			case *ProjectBillingAccount:
				email, id, status, createdAt = a.Email, a.ID, a.Status, a.CreatedAt
			case *UserBillingAccount:
				email, id, status, createdAt = a.Email, a.ID, a.Status, a.CreatedAt
			case *OrganizationBillingAccount:
				email, id, status, createdAt = a.Email, a.ID, a.Status, a.CreatedAt
			}
			if email != "" {
				details := map[string]any{
					"account_id":    id,
					"account_email": email,
					"status":        status,
					"created_at":    createdAt,
					"tenant_id":     tenantID,
				}
				err := h.NotificationService.SendNotification(
					context.Background(),
					"",
					security_management.NotificationEmail,
					[]string{email},
					"account.created",
					details,
					3,
				)
				if err != nil {
					logger.LogError("CreateAccount: onboarding notification failed", logger.ErrorField(err), logger.String("account_id", id))
				}
			}
		}(account)
	}

	// Build response with both account and tenant information
	response := map[string]interface{}{
		"account":        account,
		"tenant_id":      tenantID,
		"tenant_created": tenantCreate,
		"tenant_type":    tenantType,
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

func (h *AccountHandler) UpdateAccount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	ctx := setTenantContextForOperations(c)
	var input interface{}
	switch accountType {
	case "user":
		input = &UserBillingAccount{}
	case "organization":
		input = &OrganizationBillingAccount{}
	default:
		input = &ProjectBillingAccount{}
	}
	if err := c.BodyParser(input); err != nil {
		logger.LogError("UpdateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	switch v := input.(type) {
	case *UserBillingAccount:
		v.ID = id
	case *OrganizationBillingAccount:
		v.ID = id
	case *ProjectBillingAccount:
		v.ID = id
	}
	if v, ok := input.(interface{ Validate() *Error }); ok {
		if err := v.Validate(); err != nil {
			logger.LogError("UpdateAccount: validation failed", logger.ErrorField(err))
			return c.JSON(fiber.ErrBadRequest)
		}
	}
	account, err := h.BillingAccountService.Update(ctx, BillingAccountType(accountType), input)
	if err != nil {
		logger.LogError("UpdateAccount: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(account)
}

func (h *AccountHandler) GetAccount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	ctx := setTenantContextForOperations(c)
	account, err := h.BillingAccountService.Get(ctx, BillingAccountType(accountType), id)
	if err != nil {
		logger.LogError("GetAccount: not found", logger.ErrorField(err))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(account)
}

func (h *AccountHandler) ListAccounts(c *fiber.Ctx) error {
	accountType := c.Query("type", "project")
	var ownerID string
	switch accountType {
	case "project":
		ownerID = c.Query("project_id")
	case "user":
		ownerID = c.Query("user_id")
	case "organization":
		ownerID = c.Query("org_id")
	default:
		ownerID = ""
	}
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	ctx := setTenantContextForOperations(c)
	accounts, err := h.BillingAccountService.List(ctx, BillingAccountType(accountType), ownerID, page, pageSize)
	if err != nil {
		logger.LogError("ListAccounts: failed", logger.ErrorField(err), logger.String("owner_id", ownerID))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	if accounts == nil {
		accounts = make([]interface{}, 0)
	}
	return c.JSON(fiber.Map{"accounts": accounts, "page": page, "page_size": pageSize})
}

func (h *AccountHandler) PerformAccountAction(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("PerformAccountAction: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	var input struct {
		Action string         `json:"action"`
		Params map[string]any `json:"params"`
	}
	if err := c.BodyParser(&input); err != nil || input.Action == "" {
		logger.LogError("PerformAccountAction: action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "action required"})
	}
	ctx := setTenantContextForOperations(c)
	result, err := h.BillingAccountService.PerformAction(ctx, BillingAccountType(accountType), id, input.Action, input.Params)
	if err != nil {
		logger.LogError("PerformAccountAction: failed", logger.ErrorField(err), logger.String("account_id", id), logger.String("action", input.Action))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	if result == nil {
		result = fiber.Map{"action": input.Action, "status": "no result"}
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *AccountHandler) DeleteAccount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	ctx := setTenantContextForOperations(c)
	if err := h.BillingAccountService.Delete(ctx, BillingAccountType(accountType), id); err != nil {
		logger.LogError("DeleteAccount: failed", logger.ErrorField(err), logger.String("account_id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
