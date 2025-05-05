package tenant

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/idencode"
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
			"settings":   t.Settings,
			"created_at": t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			"updated_at": t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h *TenantHandler) GetTenantByID(c *fiber.Ctx) error {
	id, err := decodeTenantIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid tenant id"})
	}
	ctx := c.Context()
	t, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "tenant not found"})
	}
	idHash, _ := idencode.Encode(t.ID)
	resp := struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Settings  string `json:"settings"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}{
		ID:        idHash,
		Name:      t.Name,
		Settings:  t.Settings,
		CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h *TenantHandler) DeleteTenant(c *fiber.Ctx) error {
	id, err := decodeTenantIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid tenant id"})
	}
	ctx := c.Context()
	err = h.store.Delete(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "tenant not found"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func decodeTenantIDParam(c *fiber.Ctx) (string, error) {
	return idencode.Decode(c.Params("id"))
}
