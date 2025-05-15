package tax

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (h *TaxHandler) SetTaxInfo(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_info", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input TaxInfo
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.TaxInfoService.SetTaxInfo(c.Context(), input)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *TaxHandler) GetTaxInfo(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_info", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	out, err := h.TaxInfoService.GetTaxInfo(c.Context(), tenantID)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(out)
}

// --- TaxPlugin Handlers ---

func (h *TaxHandler) ListTaxPlugins(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_plugin", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	plugins, err := h.Store.ListTaxPlugins(c.Context())
	if err != nil {
		logger.LogError("ListTaxPlugins: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"plugins": plugins})
}

func (h *TaxHandler) SetTaxPluginConfig(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_plugin", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	var input struct {
		PluginName string `json:"plugin_name"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTaxPluginConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.PluginName == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "plugin_name required"})
	}
	if _, ok := TaxPlugins.Lookup(input.PluginName); !ok {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "plugin not found"})
	}
	cfg, err := h.Store.SetTaxPluginConfig(c.Context(), tenantID, input.PluginName)
	if err != nil {
		logger.LogError("SetTaxPluginConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", input.PluginName))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(cfg)
}

func (h *TaxHandler) GetTaxPluginConfig(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_plugin", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	cfg, err := h.Store.GetTaxPluginConfig(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}
