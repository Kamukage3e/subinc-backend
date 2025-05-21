package account

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// TenantMiddleware creates a middleware that validates tenant access
func TenantMiddleware(tenantStore tenant_management.TenantService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tenantID := c.Get("X-Tenant-ID")
		if tenantID == "" {
			logger.LogError("TenantMiddleware: no tenant ID provided")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing tenant ID in X-Tenant-ID header",
				"code":  "TENANT_REQUIRED",
			})
		}

		// Validate tenant exists and is active
		tenant, err := tenantStore.GetTenant(c.Context(), tenantID)
		if err != nil {
			logger.LogError("TenantMiddleware: tenant not found",
				logger.String("tenant_id", tenantID),
				logger.ErrorField(err))

			if strings.Contains(err.Error(), "tenant not found") {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "Tenant not found",
					"code":  "TENANT_NOT_FOUND",
				})
			}

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to validate tenant",
				"code":  "TENANT_VALIDATION_ERROR",
			})
		}

		if tenant.Status != tenant_management.TenantStatusActive {
			logger.LogError("TenantMiddleware: tenant not active",
				logger.String("tenant_id", tenantID),
				logger.String("status", string(tenant.Status)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Tenant not active",
				"code":  "TENANT_INACTIVE",
			})
		}

		// Set tenant context for downstream handlers
		c.Locals("tenant_id", tenantID)
		c.Locals("tenant", tenant)

		// Also set in context to be accessible in stores
		// This is used in the ListBillingAccounts and GetBillingAccount methods
		c.Context().SetUserValue("tenant_id", tenantID)

		// Add tenant ID to any existing headers for API consistency
		if c.Get("X-Tenant-ID") == "" {
			c.Request().Header.Set("X-Tenant-ID", tenantID)
		}

		// Continue
		return c.Next()
	}
}
