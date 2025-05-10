package tenant_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminTenantRoutes(router fiber.Router, handler *TenantAdminHandler) {
	tenant := router.Group("/tenant-management")

	tenant.Post("/tenants/create", handler.CreateTenant)
	tenant.Put("/tenants/update/:id", handler.UpdateTenant)
	tenant.Delete("/tenants/delete/:id", handler.DeleteTenant)
	tenant.Get("/tenants/get/:id", handler.GetTenant)
	tenant.Get("/tenants/list", handler.ListTenants)

	tenant.Get("/tenants/get/:id/settings", handler.GetTenantSettings)
	tenant.Put("/tenants/update/:id/settings", handler.UpdateTenantSettings)

}
