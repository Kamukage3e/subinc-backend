package tenant

import (
	"github.com/gofiber/fiber/v2"
)

// TenantHandler handles tenant-related endpoints
// Modular, SaaS-grade, handler-based routing
// All endpoints must be production-ready and secure

type TenantHandler struct {
	store TenantStore
}

func NewHandler(store TenantStore) *TenantHandler {
	return &TenantHandler{store: store}
}

func (h *TenantHandler) RegisterRoutes(router fiber.Router) {
	tenants := router.Group("/tenants")

	tenants.Get("/", h.ListTenants)
	tenants.Get(":id", h.GetTenantByID)
	tenants.Delete(":id", h.DeleteTenant)
}

func (h *TenantHandler) ListTenants(c *fiber.Ctx) error {
	ctx := c.Context()
	// Implement a real ListTenants method in your TenantStore for prod
	// For SaaS, this should be admin-only or scoped by org, but here we list all tenants
	// If you want to scope by user/org, extract from context as needed

	tenants, err := h.store.ListAll(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch tenants"})
	}
	resp := make([]map[string]interface{}, 0, len(tenants))
	for _, t := range tenants {
		resp = append(resp, map[string]interface{}{
			"id":         t.ID,
			"name":       t.Name,
			"created_at": t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			"updated_at": t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h *TenantHandler) GetTenantByID(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing tenant id"})
	}
	ctx := c.Context()
	t, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "tenant not found"})
	}
	resp := struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}{
		ID:        t.ID,
		Name:      t.Name,
		CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h *TenantHandler) DeleteTenant(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing tenant id"})
	}
	ctx := c.Context()
	err := h.store.Delete(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "tenant not found"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
