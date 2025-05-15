package tenant_management

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/subinc/subinc-backend/internal/pkg/contextutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// NewTenantHandler creates a new tenant handler instance
func NewTenantHandler(tenantStore TenantService, tenantSettingsStore TenantSettingsService) *TenantAdminHandler {
	return &TenantAdminHandler{
		TenantStore:         tenantStore,
		TenantSettingsStore: tenantSettingsStore,
	}
}

// Validate performs validation on tenant properties
func (t *Tenant) Validate() error {
	if t.Name == "" {
		return errors.New("tenant name must not be empty")
	}
	if len(t.Name) > 128 {
		return errors.New("tenant name too long")
	}
	return nil
}

// swagger:route POST /tenant-management/tenants tenant createTenant
// summary: Create tenant
// description: Creates a new tenant.
// tags:
//   - tenant
//
// responses:
//
//	201: Tenant
//	400: ErrorResponse
//	422: ErrorResponse
func (h *TenantAdminHandler) CreateTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("CreateTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	var tenant Tenant
	if err := c.BodyParser(&tenant); err != nil {
		logger.LogError("CreateTenant: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := tenant.Validate(); err != nil {
		logger.LogError("CreateTenant: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if err := h.TenantStore.CreateTenant(c.Context(), &tenant); err != nil {
		logger.LogError("CreateTenant: failed", logger.ErrorField(err), logger.String("name", tenant.Name))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(tenant)
}

// swagger:route GET /tenant-management/tenants/{id} tenant getTenant
// summary: Get tenant
// description: Retrieves a tenant by ID.
// tags:
//   - tenant
//
// responses:
//
//	200: Tenant
//	400: ErrorResponse
//	404: ErrorResponse
func (h *TenantAdminHandler) GetTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("GetTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetTenant: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}

	tenant, err := h.TenantStore.GetTenant(c.Context(), id)
	if err != nil {
		logger.LogError("GetTenant: failed", logger.ErrorField(err), logger.String("id", id))
		if err.Error() == "tenant not found" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "tenant not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get tenant"})
	}

	return c.Status(fiber.StatusOK).JSON(tenant)
}

// swagger:route PUT /tenant-management/tenants/{id} tenant updateTenant
// summary: Update tenant
// description: Updates an existing tenant.
// tags:
//   - tenant
//
// responses:
//
//	200: Tenant
//	400: ErrorResponse
//	422: ErrorResponse
func (h *TenantAdminHandler) UpdateTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("UpdateTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateTenant: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var tenant Tenant
	if err := c.BodyParser(&tenant); err != nil {
		logger.LogError("UpdateTenant: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	tenant.ID = id
	if err := tenant.Validate(); err != nil {
		logger.LogError("UpdateTenant: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if err := h.TenantStore.UpdateTenant(c.Context(), &tenant); err != nil {
		logger.LogError("UpdateTenant: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(tenant)
}

// swagger:route DELETE /tenant-management/tenants/{id} tenant deleteTenant
// summary: Delete tenant
// description: Deletes a tenant by ID.
// tags:
//   - tenant
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *TenantAdminHandler) DeleteTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("DeleteTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteTenant: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.TenantStore.DeleteTenant(c.Context(), id); err != nil {
		logger.LogError("DeleteTenant: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:route GET /tenant-management/tenants tenant listTenants
// summary: List tenants
// description: Lists tenants with optional filtering and pagination.
// tags:
//   - tenant
//
// responses:
//
//	200: TenantListResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *TenantAdminHandler) ListTenants(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("ListTenants: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	filter := TenantFilter{
		Query:   c.Query("query"),
		SortBy:  c.Query("sort_by"),
		SortDir: c.Query("sort_dir"),
		Limit:   c.QueryInt("limit", 100),
		Offset:  c.QueryInt("offset", 0),
	}
	tenants, total, err := h.TenantStore.SearchTenants(c.Context(), filter)
	if err != nil {
		logger.LogError("ListTenants: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list tenants"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"tenants": tenants, "total": total})
}

// swagger:route GET /tenant-management/tenants/{id}/settings tenant getTenantSettings
// summary: Get tenant settings
// description: Retrieves settings for a tenant.
// tags:
//   - tenant
//   - settings
//
// responses:
//
//	200: TenantSettings
//	400: ErrorResponse
//	404: ErrorResponse
func (h *TenantAdminHandler) GetTenantSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_settings", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantSettingsStore == nil {
		logger.LogError("GetTenantSettings: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "settings store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetTenantSettings: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	settings, err := h.TenantSettingsStore.GetTenantSettings(c.Context(), id)
	if err != nil {
		logger.LogError("GetTenantSettings: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

// swagger:route PUT /tenant-management/tenants/{id}/settings tenant updateTenantSettings
// summary: Update tenant settings
// description: Updates settings for a tenant.
// tags:
//   - tenant
//   - settings
//
// responses:
//
//	200: TenantSettings
//	400: ErrorResponse
//	422: ErrorResponse
func (h *TenantAdminHandler) UpdateTenantSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_settings", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantSettingsStore == nil {
		logger.LogError("UpdateTenantSettings: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "settings store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateTenantSettings: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input struct {
		Settings map[string]interface{} `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateTenantSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := validateTenantSettings(input.Settings); err != nil {
		logger.LogError("UpdateTenantSettings: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	settings, err := h.TenantSettingsStore.UpdateTenantSettings(c.Context(), id, input.Settings)
	if err != nil {
		logger.LogError("UpdateTenantSettings: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

// validateTenantSettings validates tenant settings for proper format and values
func validateTenantSettings(settings map[string]interface{}) error {
	// Add field-specific validation here
	if len(settings) == 0 {
		return errors.New("settings must not be empty")
	}
	return nil
}

// --- Tenant Lifecycle State Handlers ---

// swagger:route PUT /tenant-management/tenants/{id}/status tenant setTenantStatus
// summary: Set tenant status
// description: Sets the lifecycle status for a tenant.
// tags:
//   - tenant
//   - lifecycle
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *TenantAdminHandler) SetTenantStatus(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_lifecycle", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}

	var input struct {
		Status TenantStatus `json:"status"`
	}

	if err := c.BodyParser(&input); err != nil || input.Status == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "status required"})
	}

	if err := h.TenantStore.SetTenantStatus(c.Context(), id, input.Status); err != nil {
		logger.LogError("SetTenantStatus: failed", logger.ErrorField(err), logger.String("tenant_id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:route GET /tenant-management/tenants/{id}/status tenant getTenantStatus
// summary: Get tenant status
// description: Gets the lifecycle status for a tenant.
// tags:
//   - tenant
//   - lifecycle
//
// responses:
//
//	200: TenantStatusResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *TenantAdminHandler) GetTenantStatus(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := contextutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_lifecycle", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}

	status, err := h.TenantStore.GetTenantStatus(c.Context(), id)
	if err != nil {
		logger.LogError("GetTenantStatus: failed", logger.ErrorField(err), logger.String("tenant_id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"tenant_id": id, "status": status})
}
