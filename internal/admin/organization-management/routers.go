package organization_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminOrganizationRoutes(router fiber.Router, handler *OrganizationHandler) {
	org := router.Group("/organization-management")

	org.Post("/organizations/create", handler.CreateOrganization)
	org.Put("/organizations/update", handler.UpdateOrganization)
	org.Delete("/organizations/delete", handler.DeleteOrganization)
	org.Get("/organizations/get", handler.GetOrganization)
	org.Get("/organizations/list", handler.ListOrganizations)

	org.Get("/settings/get", handler.GetSettings)
	org.Put("/settings/update", handler.UpdateSettings)
}
