package tax

import (
	"fmt"
	"time"

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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	plugin, exists := TaxPlugins.Lookup(pluginName)
	if !exists {
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Tenant ID is required",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	// Check if the plugin exists
	plugin, exists := TaxPlugins.Lookup(pluginName)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Tax plugin '%s' not found", pluginName),
		})
	}

	// Parse the configuration
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid configuration format",
		})
	}

	// Initialize the plugin with the configuration
	if err := plugin.Initialize(config); err != nil {
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

// DisableTaxPlugin disables a tax plugin by name
func (h *TaxHandler) DisableTaxPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}
	// If runtime disable is not supported, return 501
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"error": "DisableTaxPlugin not implemented for this plugin type"})
}
