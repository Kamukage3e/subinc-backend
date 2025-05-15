package tax

import (
	"github.com/gofiber/fiber/v2"
)

func (h *TaxHandler) SetTaxInfo(c *fiber.Ctx) error {
	var input TaxInfo
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	info, err := h.TaxInfoService.SetTaxInfo(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(info)
}

func (h *TaxHandler) GetTaxInfo(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}
	info, err := h.TaxInfoService.GetTaxInfo(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(info)
}

// --- TaxPlugin Handlers ---

func (h *TaxHandler) ListTaxPlugins(c *fiber.Ctx) error {
	plugins, err := h.TaxInfoService.ListTaxPlugins(c.Context())
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"plugins": plugins})
}

func (h *TaxHandler) SetTaxPluginConfig(c *fiber.Ctx) error {
	var input TaxPluginConfig
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.TenantID = c.Params("tenant_id")
	config, err := h.TaxInfoService.SetTaxPluginConfig(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(config)
}

func (h *TaxHandler) GetTaxPluginConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}
	config, err := h.TaxInfoService.GetTaxPluginConfig(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(config)
}
