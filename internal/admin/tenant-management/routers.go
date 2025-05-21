package tenant_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)


// RegisterRoutes registers all tenant management routes
// Uses standard RESTful conventions:
// - GET collection: list resource
// - GET item: get single resource
// - POST collection: create resource
// - PUT item: update resource
// - DELETE item: delete resource
func RegisterRoutes(router fiber.Router, handler *TenantAdminHandler, jwtSecret string) {
	route := router.Group(
		"/tenant-management",
		security_management.OIDCMiddleware(jwtSecret),
	)

	// Tenants CRUD
	route.Post("/tenants", rbacmiddleware.RBACMiddleware("tenant", "create", nil), handler.CreateTenant)
	route.Get("/tenants", rbacmiddleware.RBACMiddleware("tenant", "read", nil), handler.ListTenants)
	route.Get("/tenants/:id", rbacmiddleware.RBACMiddleware("tenant", "read", nil), handler.GetTenant)
	route.Put("/tenants/:id", rbacmiddleware.RBACMiddleware("tenant", "update", nil), handler.UpdateTenant)
	route.Delete("/tenants/:id", rbacmiddleware.RBACMiddleware("tenant", "delete", nil), handler.DeleteTenant)

	// Settings
	route.Get("/tenants/:id/settings", rbacmiddleware.RBACMiddleware("tenant-settings", "read", nil), handler.GetTenantSettings)
	route.Put("/tenants/:id/settings", rbacmiddleware.RBACMiddleware("tenant-settings", "update", nil), handler.UpdateTenantSettings)

	// Status
	route.Get("/tenants/:id/status", rbacmiddleware.RBACMiddleware("tenant-status", "read", nil), handler.GetTenantStatus)
	route.Put("/tenants/:id/status", rbacmiddleware.RBACMiddleware("tenant-status", "update", nil), handler.SetTenantStatus)

	// Tenant Provisioning and Isolation
	route.Post("/tenants/provision", rbacmiddleware.RBACMiddleware("tenant", "create", nil), handler.ProvisionTenant)
	route.Get("/tenants/:id/verify-isolation", rbacmiddleware.RBACMiddleware("tenant", "read", nil), handler.VerifyTenantIsolation)

	// Tenant Migration
	route.Post("/tenants/:id/migrate", rbacmiddleware.RBACMiddleware("tenant-migration", "create", nil), handler.MigrateTenant)
	route.Get("/tenants/:id/export", rbacmiddleware.RBACMiddleware("tenant-migration", "read", nil), handler.ExportTenantData)
	route.Post("/tenants/:id/import", rbacmiddleware.RBACMiddleware("tenant-migration", "create", nil), handler.ImportTenantData)
}
