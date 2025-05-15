package tenant_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func tenantScopeExtractor(c *fiber.Ctx) (string, string) {
	return "tenant", c.Get("X-Tenant-ID")
}

func RegisterRoutes(router fiber.Router, handler *TenantAdminHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/tenant-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, tenantScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	// Tenants CRUD
	route.Post("/tenants", handler.CreateTenant)
	route.Get("/tenants", handler.ListTenants)
	route.Get("/tenants/:id", handler.GetTenant)
	route.Put("/tenants/:id", handler.UpdateTenant)
	route.Delete("/tenants/:id", handler.DeleteTenant)
	// Settings
	route.Get("/tenants/:id/settings", handler.GetTenantSettings)
	route.Put("/tenants/:id/settings", handler.UpdateTenantSettings)
	// Status
	route.Get("/tenants/:id/status", handler.GetTenantStatus)
	route.Put("/tenants/:id/status", handler.SetTenantStatus)
}
