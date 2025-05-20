package tax

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	apierrors "github.com/subinc/subinc-backend/internal/pkg/errors"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (h *TaxHandler) SetTaxInfo(c *fiber.Ctx) error {
	var input TaxInfo
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTaxInfo: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	info, err := h.TaxInfoService.SetTaxInfo(c.Context(), input)
	if err != nil {
		logger.LogError("SetTaxInfo: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(info)
}

func (h *TaxHandler) GetTaxInfo(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetTaxInfo: tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}
	info, err := h.TaxInfoService.GetTaxInfo(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetTaxInfo: failed to get tax info", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(info)
}

// --- TaxPlugin Handlers ---

// ListTaxPlugins returns all registered tax plugins
func (h *TaxHandler) ListTaxPlugins(c *fiber.Ctx) error {
	pluginNames := TaxPlugins.List()

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
			"error": "Plugin name is required",
		})
	}

	plugin, exists := TaxPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("GetTaxPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Tax plugin '%s' not found", pluginName),
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
			"error": "Tenant ID is required",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("ConfigureTaxPlugin: plugin name required", logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	// Check if the plugin exists
	plugin, exists := TaxPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("ConfigureTaxPlugin: plugin not found",
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Tax plugin '%s' not found", pluginName),
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
			"error": "Invalid configuration format",
		})
	}

	// Initialize the plugin with the configuration
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("ConfigureTaxPlugin: failed to initialize plugin",
			logger.ErrorField(err),
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to initialize plugin: %v", err),
		})
	}

	// Create a TaxPluginConfig for storage
	pluginConfig := TaxPluginConfig{
		TenantID:   tenantID,
		PluginName: pluginName,
		UpdatedAt:  time.Now(),
	}

	// Save the configuration
	ctx := c.Context()
	savedConfig, err := h.TaxInfoService.SetTaxPluginConfig(ctx, pluginConfig)
	if err != nil {
		logger.LogError("ConfigureTaxPlugin: failed to save plugin configuration",
			logger.ErrorField(err),
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to save plugin configuration: %v", err),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Tax plugin '%s' configured successfully for tenant '%s'", pluginName, tenantID),
		"config":  savedConfig,
	})
}

func (h *TaxHandler) SetTaxPluginConfig(c *fiber.Ctx) error {
	var input TaxPluginConfig
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTaxPluginConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.TenantID = c.Params("tenant_id")
	config, err := h.TaxInfoService.SetTaxPluginConfig(c.Context(), input)
	if err != nil {
		logger.LogError("SetTaxPluginConfig: failed",
			logger.ErrorField(err),
			logger.String("tenant_id", input.TenantID),
			logger.String("plugin_name", input.PluginName))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(config)
}

func (h *TaxHandler) GetTaxPluginConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetTaxPluginConfig: tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}
	config, err := h.TaxInfoService.GetTaxPluginConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetTaxPluginConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(config)
}

// DisableTaxPlugin disables a tax plugin by name
func (h *TaxHandler) DisableTaxPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("DisableTaxPlugin: plugin name required", logger.String("path", c.Path()))
		return apierrors.NewBadRequestError("plugin name is required")
	}

	// If plugin exists but doesn't support disabling
	plugin, exists := TaxPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("DisableTaxPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return apierrors.NewNotFoundError("tax plugin")
	}

	// Check if plugin implements the Disableable interface
	disableable, ok := plugin.(DisableableTaxPlugin)
	if !ok {
		logger.LogError("DisableTaxPlugin: plugin does not support disabling", logger.String("plugin_name", pluginName))
		// Use our standardized "not implemented" error with richer context
		return apierrors.NewNotImplementedError("disabling tax plugin")
	}

	// Attempt to disable the plugin
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("DisableTaxPlugin: tenant_id required", logger.String("plugin_name", pluginName))
		return apierrors.NewBadRequestError("tenant_id is required")
	}

	if err := disableable.Disable(); err != nil {
		logger.LogError("DisableTaxPlugin: failed to disable plugin",
			logger.ErrorField(err),
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return apierrors.NewInternalError(err).WithError(err)
	}

	// Remove the plugin configuration for this tenant
	if err := h.TaxInfoService.RemoveTaxPluginConfig(c.Context(), tenantID, pluginName); err != nil {
		logger.LogError("DisableTaxPlugin: failed to remove plugin config",
			logger.ErrorField(err),
			logger.String("plugin_name", pluginName),
			logger.String("tenant_id", tenantID))
		return apierrors.NewInternalError(err).WithError(err)
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Tax plugin '%s' disabled successfully", pluginName),
	})
}
