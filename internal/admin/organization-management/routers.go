package organization_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterRoutes(router fiber.Router, handler *OrganizationHandler, jwtSecretName string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/organizations",
		security_management.OIDCMiddleware(jwtSecretName),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, orgScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)

	route.Post("/", handler.CreateOrganization)
	route.Get("/", handler.ListOrganizations)
	route.Get("/:id", handler.GetOrganization)
	route.Put("/:id", handler.UpdateOrganization)
	route.Delete("/:id", handler.DeleteOrganization)
	route.Get("/:id/settings", handler.GetSettings)
	route.Put("/:id/settings", handler.UpdateSettings)
}

func orgScopeExtractor(c *fiber.Ctx) (string, string) {
	return "org", c.Get("X-Org-ID")
}
