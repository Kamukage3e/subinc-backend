package tenant_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminTenantRoutes(router fiber.Router, handler *TenantAdminHandler) {
	tenant := router.Group("/tenant-management")

	tenant.Post("/tenants/create", handler.CreateTenant)
	tenant.Post("/tenants/update", handler.UpdateTenant)
	tenant.Post("/tenants/delete", handler.DeleteTenant)
	tenant.Post("/tenants/get", handler.GetTenant)
	tenant.Post("/tenants/list", handler.ListTenants)

	tenant.Post("/tenants/get-settings", handler.GetTenantSettings)
	tenant.Post("/tenants/update-settings", handler.UpdateTenantSettings)
}
