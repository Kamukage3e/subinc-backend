package tenant

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/idencode"
)

// Modular, SaaS-grade, handler-based routing. All endpoints must be production-ready and secure.

func NewHandler(store TenantStore) *TenantHandler {
	return &TenantHandler{store: store}
}

func (h *TenantHandler) ListTenants(c *fiber.Ctx) error {
	ctx := c.Context()
	tenants, err := h.store.ListAll(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch tenants"})
	}
	if len(tenants) == 0 {
		return c.Status(fiber.StatusOK).JSON([]interface{}{})
	}
	resp := make([]fiber.Map, 0, len(tenants))
	for _, t := range tenants {
		resp = append(resp, fiber.Map{
			"id":         t.ID,
			"name":       t.Name,
			"settings":   t.Settings,
			"created_at": t.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			"updated_at": t.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
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
