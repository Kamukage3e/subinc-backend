package tax

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (h *TaxHandler) SetTaxInfo(c *fiber.Ctx) error {
	var input TaxInfo
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTaxInfo: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	info, err := h.TaxInfoService.SetTaxInfo(c.Context(), input)
	if err != nil {
		logger.LogError("SetTaxInfo: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.Status(fiber.StatusCreated).JSON(info)
}

func (h *TaxHandler) GetTaxInfo(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetTaxInfo: tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}

	info, err := h.TaxInfoService.GetTaxInfo(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetTaxInfo: failed to get tax info", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.JSON(info)
}

// --- TaxPlugin Handlers ---

// ListTaxPlugins returns all registered tax plugins
func (h *TaxHandler) ListTaxPlugins(c *fiber.Ctx) error {
	pluginNames, err := h.TaxInfoService.ListTaxPlugins(c.Context())
	if err != nil {
		logger.LogError("ListTaxPlugins: failed to list plugins", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	if len(pluginNames) == 0 {
		logger.LogInfo("ListTaxPlugins: no plugins found")
	}

	return c.JSON(fiber.Map{
		"plugins": pluginNames,
	})
}

// GetTaxPlugin returns details about a specific tax plugin
func (h *TaxHandler) GetTaxPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("GetTaxPlugin: plugin name required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	plugin, err := h.TaxInfoService.GetTaxPlugin(c.Context(), pluginName)
	if err != nil {
		if err == ErrPluginNotFound {
			logger.LogError("GetTaxPlugin: plugin not found", logger.String("plugin_name", pluginName))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Resource not found",
			})
		}
		logger.LogError("GetTaxPlugin: failed to get plugin", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.JSON(fiber.Map{
		"name":         plugin.Name(),
		"version":      plugin.Version(),
		"capabilities": plugin.Capabilities(),
	})
}

// ConfigureTaxPlugin configures a tax plugin for a tenant
func (h *TaxHandler) ConfigureTaxPlugin(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("ConfigureTaxPlugin: tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("ConfigureTaxPlugin: plugin name required", logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	// Parse the configuration
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("ConfigureTaxPlugin: invalid configuration format",
			logger.ErrorField(err),
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	// Configure the plugin using the service
	if err := h.TaxInfoService.ConfigureTaxPlugin(c.Context(), pluginName, tenantID, config); err != nil {
		if err == ErrPluginNotFound {
			logger.LogError("ConfigureTaxPlugin: plugin not found",
				logger.String("plugin_name", pluginName),
				logger.String("tenant_id", tenantID))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Resource not found",
			})
		}
		logger.LogError("ConfigureTaxPlugin: failed to configure plugin",
			logger.ErrorField(err),
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Tax plugin configured successfully",
	})
}

func (h *TaxHandler) SetTaxPluginConfig(c *fiber.Ctx) error {
	var input TaxPluginConfig
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTaxPluginConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	input.TenantID = c.Params("tenant_id")
	if input.TenantID == "" {
		logger.LogError("SetTaxPluginConfig: tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}

	config, err := h.TaxInfoService.SetTaxPluginConfig(c.Context(), input)
	if err != nil {
		logger.LogError("SetTaxPluginConfig: failed",
			logger.ErrorField(err),
			logger.String("tenant_id", input.TenantID),
			logger.String("plugin_name", input.PluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.Status(fiber.StatusCreated).JSON(config)
}

func (h *TaxHandler) GetTaxPluginConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetTaxPluginConfig: tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}

	config, err := h.TaxInfoService.GetTaxPluginConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetTaxPluginConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.JSON(config)
}

// DisableTaxPlugin disables a tax plugin by name
func (h *TaxHandler) DisableTaxPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("DisableTaxPlugin: plugin name required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("DisableTaxPlugin: tenant_id required", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	// Use the proper service method to handle the plugin disabling
	if err := h.TaxInfoService.RemoveTaxPluginConfig(c.Context(), tenantID, pluginName); err != nil {
		logger.LogError("DisableTaxPlugin: failed to remove plugin config",
			logger.ErrorField(err),
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "Tax plugin disabled successfully",
	})
}
