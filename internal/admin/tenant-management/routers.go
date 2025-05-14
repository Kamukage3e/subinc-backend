package tenant_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func tenantScopeExtractor(c *fiber.Ctx) (string, string) {
	return "tenant", c.Get("X-Tenant-ID")
}

func RegisterAdminTenantRoutes(router fiber.Router, handler *TenantAdminHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	tenant := router.Group(
		"/tenant-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, tenantScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	tenant.Post("/tenants/create", handler.CreateTenant)
	tenant.Post("/tenants/update", handler.UpdateTenant)
	tenant.Post("/tenants/delete", handler.DeleteTenant)
	tenant.Post("/tenants/get", handler.GetTenant)
	tenant.Post("/tenants/list", handler.ListTenants)

	tenant.Post("/tenants/get-settings", handler.GetTenantSettings)
	tenant.Post("/tenants/update-settings", handler.UpdateTenantSettings)

	tenant.Post("/tenants/set-status", handler.SetTenantStatus)
	tenant.Get("/tenants/get-status", handler.GetTenantStatus)
}
