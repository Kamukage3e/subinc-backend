package tenant_management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type TenantAdminHandler struct {
	TenantStore         *TenantStore
	TenantSettingsStore *TenantSettingsStore
}

func (h *TenantAdminHandler) CreateTenant(c *fiber.Ctx) error {
	if h.TenantStore == nil {
		logger.LogError("CreateTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	var tenant Tenant
	if err := c.BodyParser(&tenant); err != nil {
		logger.LogError("CreateTenant: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if tenant.Name == "" {
		logger.LogError("CreateTenant: name required", logger.String("name", tenant.Name))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name required"})
	}
	if err := h.TenantStore.CreateTenant(c.Context(), &tenant); err != nil {
		logger.LogError("CreateTenant: failed", logger.ErrorField(err), logger.String("name", tenant.Name))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(tenant)
}

func (h *TenantAdminHandler) UpdateTenant(c *fiber.Ctx) error {
	if h.TenantStore == nil {
		logger.LogError("UpdateTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateTenant: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var tenant Tenant
	if err := c.BodyParser(&tenant); err != nil {
		logger.LogError("UpdateTenant: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	tenant.ID = id
	if err := h.TenantStore.UpdateTenant(c.Context(), &tenant); err != nil {
		logger.LogError("UpdateTenant: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(tenant)
}

func (h *TenantAdminHandler) DeleteTenant(c *fiber.Ctx) error {
	if h.TenantStore == nil {
		logger.LogError("DeleteTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteTenant: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.TenantStore.DeleteTenant(c.Context(), id); err != nil {
		logger.LogError("DeleteTenant: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *TenantAdminHandler) GetTenant(c *fiber.Ctx) error {
	if h.TenantStore == nil {
		logger.LogError("GetTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetTenant: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	// ListTenants and filter (replace with GetTenantByID if needed)
	tenants, err := h.TenantStore.ListTenants(c.Context())
	if err != nil {
		logger.LogError("GetTenant: failed to list tenants", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch tenants"})
	}
	for _, t := range tenants {
		if tenant, ok := t.(Tenant); ok && tenant.ID == id {
			return c.Status(fiber.StatusOK).JSON(tenant)
		}
	}
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "tenant not found"})
}

func (h *TenantAdminHandler) ListTenants(c *fiber.Ctx) error {
	if h.TenantStore == nil {
		logger.LogError("ListTenants: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	query := c.Query("q", "")
	sortBy := c.Query("sort_by", "created_at")
	sortDir := c.Query("sort_dir", "DESC")
	limit := c.QueryInt("limit", 100)
	offset := c.QueryInt("offset", 0)
	if limit < 1 {
		limit = 10
	} else if limit > 1000 {
		limit = 1000
	}
	filter := TenantFilter{
		Query:   query,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	tenants, total, err := h.TenantStore.SearchTenants(c.Context(), filter)
	if err != nil {
		logger.LogError("ListTenants: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list tenants"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"tenants": tenants, "total": total})
}

func (h *TenantAdminHandler) GetTenantSettings(c *fiber.Ctx) error {
	tenantID := c.Params("id")
	if tenantID == "" {
		logger.LogError("GetTenantSettings: id required", logger.String("id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if h.TenantSettingsStore == nil {
		logger.LogError("GetTenantSettings: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "settings store not configured"})
	}
	settings, err := h.TenantSettingsStore.GetTenantSettings(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetTenantSettings: failed", logger.ErrorField(err), logger.String("id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

func (h *TenantAdminHandler) UpdateTenantSettings(c *fiber.Ctx) error {
	tenantID := c.Params("id")
	if tenantID == "" {
		logger.LogError("UpdateTenantSettings: id required", logger.String("id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateTenantSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if h.TenantSettingsStore == nil {
		logger.LogError("UpdateTenantSettings: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "settings store not configured"})
	}
	settings, err := h.TenantSettingsStore.UpdateTenantSettings(c.Context(), tenantID, input)
	if err != nil {
		logger.LogError("UpdateTenantSettings: failed", logger.ErrorField(err), logger.String("id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}
