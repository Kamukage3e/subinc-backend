package tenant

import (
	"github.com/gofiber/fiber/v2"
)

type Deps struct {
	TenantHandler *TenantHandler
}

func RegisterRoutes(router fiber.Router, deps Deps) {
	tenantGroup := router.Group("/tenants")
	tenantGroup.Get("/", deps.TenantHandler.ListTenants)
	tenantGroup.Get(":id", deps.TenantHandler.GetTenantByID)
	tenantGroup.Delete(":id", deps.TenantHandler.DeleteTenant)
}
