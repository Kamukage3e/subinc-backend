package tenant_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

// tenantScopeExtractor extracts tenant-specific identifiers for rate limiting
func tenantScopeExtractor(c *fiber.Ctx) (string, string) {
	return "tenant", c.Get("X-Tenant-ID")
}

// RegisterRoutes registers all tenant management routes
// Uses standard RESTful conventions:
// - GET collection: list resource
// - GET item: get single resource
// - POST collection: create resource
// - PUT item: update resource
// - DELETE item: delete resource
func RegisterRoutes(router fiber.Router, handler *TenantAdminHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/tenant-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, tenantScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	// Tenants CRUD
	route.Post("/tenants", handler.CreateTenant)       // Create tenant
	route.Get("/tenants", handler.ListTenants)         // List/search tenants with pagination
	route.Get("/tenants/:id", handler.GetTenant)       // Get tenant by ID
	route.Put("/tenants/:id", handler.UpdateTenant)    // Update tenant
	route.Delete("/tenants/:id", handler.DeleteTenant) // Delete tenant

	// Settings
	route.Get("/tenants/:id/settings", handler.GetTenantSettings)    // Get tenant settings
	route.Put("/tenants/:id/settings", handler.UpdateTenantSettings) // Update tenant settings

	// Status
	route.Get("/tenants/:id/status", handler.GetTenantStatus) // Get tenant lifecycle status
	route.Put("/tenants/:id/status", handler.SetTenantStatus) // Update tenant lifecycle status
}
