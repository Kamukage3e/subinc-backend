package fee

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type FeeHandler struct {
	Store *PostgresStore
}

func (h *FeeHandler) CreateFee(c *fiber.Ctx) error {
	var fee Fee
	if err := c.BodyParser(&fee); err != nil {
		logger.LogError("CreateFee: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if vErr := fee.Validate(); vErr != nil {
		logger.LogError("CreateFee: validation failed", logger.ErrorField(vErr))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": vErr.Error()})
	}
	created, err := h.Store.CreateFee(context.Background(), fee)
	if err != nil {
		logger.LogError("CreateFee: store error", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

func (h *FeeHandler) GetFee(c *fiber.Ctx) error {
	id := c.Params("id")
	fee, err := h.Store.GetFee(context.Background(), id)
	if err != nil {
		logger.LogError("GetFee: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fee)
}

func (h *FeeHandler) UpdateFee(c *fiber.Ctx) error {
	id := c.Params("id")
	var fee Fee
	if err := c.BodyParser(&fee); err != nil {
		logger.LogError("UpdateFee: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	fee.ID = id
	if vErr := fee.Validate(); vErr != nil {
		logger.LogError("UpdateFee: validation failed", logger.ErrorField(vErr))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": vErr.Error()})
	}
	updated, err := h.Store.UpdateFee(context.Background(), fee)
	if err != nil {
		logger.LogError("UpdateFee: store error", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(updated)
}

func (h *FeeHandler) DeleteFee(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.Store.DeleteFee(context.Background(), id); err != nil {
		logger.LogError("DeleteFee: store error", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *FeeHandler) SetFeePluginConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID   string `json:"tenant_id"`
		PluginName string `json:"plugin_name"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetFeePluginConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	cfg, err := h.Store.SetFeePluginConfig(c.Context(), input.TenantID, input.PluginName)
	if err != nil {
		logger.LogError("SetFeePluginConfig: store error", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *FeeHandler) GetFeePluginConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	cfg, err := h.Store.GetFeePluginConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetFeePluginConfig: not found", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *FeeHandler) ListFees(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	fees, err := h.Store.ListFees(context.Background(), page, pageSize)
	if err != nil {
		logger.LogError("ListFees: store error", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"fees": fees, "page": page, "page_size": pageSize})
}

// ListFeePlugins returns all registered fee plugins
func (h *FeeHandler) ListFeePlugins(c *fiber.Ctx) error {
	pluginNames := FeePlugins.List()
	return c.JSON(fiber.Map{"plugins": pluginNames})
}

// GetFeePlugin returns details about a specific fee plugin
func (h *FeeHandler) GetFeePlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}
	plugin, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Fee plugin '" + pluginName + "' not found"})
	}
	return c.JSON(fiber.Map{
		"name":         plugin.Name(),
		"version":      plugin.Version(),
		"capabilities": plugin.Capabilities(),
	})
}

// ConfigureFeePlugin is a stub for plugin configuration
func (h *FeeHandler) ConfigureFeePlugin(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"error": "ConfigureFeePlugin not implemented for this plugin type"})
}

// DisableFeePlugin disables a fee plugin by name
func (h *FeeHandler) DisableFeePlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"error": "DisableFeePlugin not implemented for this plugin type"})
}
