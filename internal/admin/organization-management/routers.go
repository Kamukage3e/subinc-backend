package organization_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

func orgScopeExtractor(c *fiber.Ctx) (string, string) {
	return "org", c.Get("X-Org-ID")
}

func RegisterAdminOrganizationRoutes(router fiber.Router, handler *OrganizationHandler, jwtSecret string) {
	org := router.Group(
		"/organization-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, orgScopeExtractor),
	)

	org.Post("/organizations/create", handler.CreateOrganization)
	org.Put("/organizations/update", handler.UpdateOrganization)
	org.Delete("/organizations/delete", handler.DeleteOrganization)
	org.Get("/organizations/get", handler.GetOrganization)
	org.Get("/organizations/list", handler.ListOrganizations)

	org.Get("/settings/get", handler.GetSettings)
	org.Put("/settings/update", handler.UpdateSettings)
}
