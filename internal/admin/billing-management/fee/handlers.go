package fee

import (
	"context"
	"reflect"

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
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

func (h *FeeHandler) GetFee(c *fiber.Ctx) error {
	id := c.Params("id")
	fee, err := h.Store.GetFee(context.Background(), id)
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": vErr.Error()})
	}
	updated, err := h.Store.UpdateFee(context.Background(), fee)
	if err != nil {
		logger.LogError("UpdateFee: store error", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(updated)
}

func (h *FeeHandler) DeleteFee(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.Store.DeleteFee(context.Background(), id); err != nil {
		logger.LogError("DeleteFee: store error", logger.ErrorField(err), logger.String("id", id))
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
	cfg, err := h.Store.SetFeePluginConfig(c.Context(), input.TenantID, input.PluginName)
	if err != nil {
		logger.LogError("SetFeePluginConfig: store error", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

func (h *FeeHandler) GetFeePluginConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	cfg, err := h.Store.GetFeePluginConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetFeePluginConfig: not found", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(cfg)
}

func (h *FeeHandler) ListFees(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	fees, err := h.Store.ListFees(context.Background(), page, pageSize)
	if err != nil {
		logger.LogError("ListFees: store error", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(fiber.Map{"fees": fees, "page": page, "page_size": pageSize})
}

// ListFeePlugins returns all registered fee plugins
func (h *FeeHandler) ListFeePlugins(c *fiber.Ctx) error {
	pluginNames := FeePlugins.List()
	if pluginNames == nil {
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
	plugin, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("GetFeePlugin: plugin not found", logger.String("plugin_name", pluginName))
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

	// Check if plugin exists first
	plugin, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("ConfigureFeePlugin: plugin not found", logger.String("plugin_name", pluginName))
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}

	cfg, err := h.Store.SetFeePluginConfig(c.Context(), input.TenantID, pluginName)
	if err != nil {
		logger.LogError("ConfigureFeePlugin: store error", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to configure plugin"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"config":  cfg,
		"plugin": map[string]string{
			"name":    plugin.Name(),
			"version": plugin.Version(),
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

	// Check if plugin exists
	_, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("DisableFeePlugin: plugin not found", logger.String("plugin_name", pluginName))
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}

	err := h.Store.DisableFeePlugin(c.Context(), input.TenantID, pluginName)
	if err != nil {
		logger.LogError("DisableFeePlugin: store error", logger.ErrorField(err),
			logger.String("tenant_id", input.TenantID),
			logger.String("plugin_name", pluginName))

		if _, ok := err.(*ValidationError); ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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

	// Verify plugin exists in registry (should have been registered at startup)
	plugin, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("RegisterFeePlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Fee plugin '" + pluginName + "' not found"})
	}

	// Get configuration for plugin initialization
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("RegisterFeePlugin: invalid config", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid configuration format"})
	}

	// Check if plugin supports Initialize method via reflection
	pluginType := reflect.TypeOf(plugin)
	if _, exists := pluginType.MethodByName("Initialize"); !exists {
		logger.LogError("RegisterFeePlugin: plugin does not support initialization", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin does not support initialization"})
	}

	// Call Initialize method via reflection
	initializeMethod := reflect.ValueOf(plugin).MethodByName("Initialize")
	results := initializeMethod.Call([]reflect.Value{reflect.ValueOf(config)})
	if len(results) > 0 && !results[0].IsNil() {
		err := results[0].Interface().(error)
		logger.LogError("RegisterFeePlugin: initialization failed", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to initialize plugin: " + err.Error()})
	}

	logger.LogInfo("RegisterFeePlugin: plugin initialized successfully", logger.String("plugin_name", pluginName))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Fee plugin '" + pluginName + "' registered and initialized successfully",
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

	// Check if plugin exists before unregistering
	plugin, exists := FeePlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("UnregisterFeePlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Fee plugin '" + pluginName + "' not found"})
	}

	// Check if plugin is in use by any tenants
	// This would require a database query to check if any tenant has this plugin configured
	// For now, just log the unregister action

	// Unregister from global registry - we need to add this method to the registry
	// Since the RegisterFeePlugin function uses FeePlugins.Register(), we need a corresponding Unregister method

	// Update the plugin registry
	FeePlugins.Unregister(pluginName)

	logger.LogInfo("UnregisterFeePlugin: plugin unregistered", logger.String("plugin_name", pluginName))
	return c.JSON(fiber.Map{
		"success": true,
		"message": "Fee plugin '" + pluginName + "' unregistered successfully",
		"plugin": map[string]string{
			"name":    plugin.Name(),
			"version": plugin.Version(),
		},
	})
}
