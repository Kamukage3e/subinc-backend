package fee

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type FeeHandler struct {
	Service FeeService
}

func NewFeeHandler(service FeeService) *FeeHandler {
	return &FeeHandler{
		Service: service,
	}
}

func (h *FeeHandler) CreateFee(c *fiber.Ctx) error {
	var fee Fee
	if err := c.BodyParser(&fee); err != nil {
		logger.LogError("CreateFee: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if vErr := fee.Validate(); vErr != nil {
		logger.LogError("CreateFee: validation failed", logger.ErrorField(vErr))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "Validation failed. Please check your input."})
	}
	created, err := h.Service.CreateFee(context.Background(), fee)
	if err != nil {
		logger.LogError("CreateFee: service error", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

func (h *FeeHandler) GetFee(c *fiber.Ctx) error {
	id := c.Params("id")
	fee, err := h.Service.GetFee(context.Background(), id)
	if err != nil {
		logger.LogError("GetFee: not found", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrNotFound)
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "Validation failed. Please check your input."})
	}
	updated, err := h.Service.UpdateFee(context.Background(), fee)
	if err != nil {
		logger.LogError("UpdateFee: service error", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(updated)
}

func (h *FeeHandler) DeleteFee(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.Service.DeleteFee(context.Background(), id); err != nil {
		logger.LogError("DeleteFee: service error", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrBadRequest)
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
	cfg, err := h.Service.SetFeePluginConfig(c.Context(), input.TenantID, input.PluginName)
	if err != nil {
		logger.LogError("SetFeePluginConfig: service error", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

func (h *FeeHandler) GetFeePluginConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	cfg, err := h.Service.GetFeePluginConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetFeePluginConfig: not found", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(cfg)
}

func (h *FeeHandler) ListFees(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	fees, err := h.Service.ListFees(context.Background(), page, pageSize)
	if err != nil {
		logger.LogError("ListFees: service error", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(fiber.Map{"fees": fees, "page": page, "page_size": pageSize})
}

// ListFeePlugins returns all registered fee plugins
func (h *FeeHandler) ListFeePlugins(c *fiber.Ctx) error {
	pluginNames, err := h.Service.ListFeePlugins(c.Context())
	if err != nil {
		logger.LogError("ListFeePlugins: failed to list plugins", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to list fee plugins"})
	}

	if len(pluginNames) == 0 {
		logger.LogError("ListFeePlugins: no plugins found")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "No fee plugins found"})
	}
	return c.JSON(fiber.Map{"plugins": pluginNames})
}

// GetFeePlugin returns details about a specific fee plugin
func (h *FeeHandler) GetFeePlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("GetFeePlugin: plugin name required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}

	plugin, err := h.Service.GetFeePlugin(c.Context(), pluginName)
	if err != nil {
		logger.LogError("GetFeePlugin: plugin not found", logger.ErrorField(err), logger.String("plugin_name", pluginName))
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
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("ConfigureFeePlugin: plugin name required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}

	// Verify the plugin exists first
	_, err := h.Service.GetFeePlugin(c.Context(), pluginName)
	if err != nil {
		logger.LogError("ConfigureFeePlugin: plugin not found", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Fee plugin '" + pluginName + "' not found"})
	}

	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ConfigureFeePlugin: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input format"})
	}

	if input.TenantID == "" {
		logger.LogError("ConfigureFeePlugin: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	cfg, err := h.Service.SetFeePluginConfig(c.Context(), input.TenantID, pluginName)
	if err != nil {
		logger.LogError("ConfigureFeePlugin: service error", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to configure plugin"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"config":  cfg,
		"plugin": map[string]string{
			"name":    pluginName,
			"version": "latest", // Use actual version if available in cfg
		},
	})
}

// DisableFeePlugin disables a fee plugin by name
func (h *FeeHandler) DisableFeePlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("DisableFeePlugin: plugin name required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}

	// Verify the plugin exists
	_, err := h.Service.GetFeePlugin(c.Context(), pluginName)
	if err != nil {
		logger.LogError("DisableFeePlugin: plugin not found", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Fee plugin '" + pluginName + "' not found"})
	}

	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("DisableFeePlugin: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input format"})
	}

	if input.TenantID == "" {
		logger.LogError("DisableFeePlugin: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	err = h.Service.DisableFeePlugin(c.Context(), input.TenantID, pluginName)
	if err != nil {
		logger.LogError("DisableFeePlugin: service error", logger.ErrorField(err),
			logger.String("tenant_id", input.TenantID),
			logger.String("plugin_name", pluginName))

		if _, ok := err.(*ValidationError); ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid plugin configuration"})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to disable plugin"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Fee plugin '" + pluginName + "' disabled for tenant " + input.TenantID,
	})
}

// RegisterFeePlugin registers and initializes a fee plugin
func (h *FeeHandler) RegisterFeePlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("RegisterFeePlugin: plugin name required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}

	// Get configuration for plugin initialization
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("RegisterFeePlugin: invalid config", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid configuration format"})
	}

	// Register and initialize the plugin
	err := h.Service.RegisterFeePlugin(c.Context(), pluginName, config)
	if err != nil {
		logger.LogError("RegisterFeePlugin: failed to register plugin", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register plugin"})
	}

	// Get the plugin to return its information
	plugin, err := h.Service.GetFeePlugin(c.Context(), pluginName)
	if err != nil {
		logger.LogError("RegisterFeePlugin: plugin not found after registration", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Plugin registered but could not be retrieved"})
	}

	logger.LogInfo("RegisterFeePlugin: plugin initialized successfully", logger.String("plugin_name", pluginName))
	return c.JSON(fiber.Map{
		"success": true,
		"message": fmt.Sprintf("Plugin '%s' registered and initialized successfully", pluginName),
		"plugin": map[string]string{
			"name":    plugin.Name(),
			"version": plugin.Version(),
		},
	})
}

// UnregisterFeePlugin unregisters a fee plugin
func (h *FeeHandler) UnregisterFeePlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("UnregisterFeePlugin: plugin name required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}

	// Get the plugin first to confirm it exists and get details for the response
	plugin, err := h.Service.GetFeePlugin(c.Context(), pluginName)
	if err != nil {
		logger.LogError("UnregisterFeePlugin: plugin not found", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": fmt.Sprintf("Fee plugin '%s' not found", pluginName)})
	}

	// Capture plugin info before unregistering
	pluginInfo := map[string]string{
		"name":    plugin.Name(),
		"version": plugin.Version(),
	}

	// Unregister the plugin
	err = h.Service.UnregisterFeePlugin(c.Context(), pluginName)
	if err != nil {
		logger.LogError("UnregisterFeePlugin: failed to unregister", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to unregister plugin"})
	}

	logger.LogInfo("UnregisterFeePlugin: plugin unregistered", logger.String("plugin_name", pluginName))
	return c.JSON(fiber.Map{
		"success": true,
		"message": fmt.Sprintf("Fee plugin '%s' unregistered successfully", pluginName),
		"plugin":  pluginInfo,
	})
}
