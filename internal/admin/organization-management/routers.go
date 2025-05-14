package organization_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func orgScopeExtractor(c *fiber.Ctx) (string, string) {
	return "org", c.Get("X-Org-ID")
}

func RegisterAdminOrganizationRoutes(router fiber.Router, handler *OrganizationHandler, jwtSecretName string, auditLogger security_management.AuditLogger) {
	org := router.Group(
		"/organization-management",
		security_management.OIDCMiddleware(jwtSecretName),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, orgScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	// audit := auditmiddleware.AuditLoggerMiddleware(auditLogger)
	org.Post("/organizations/create", handler.CreateOrganization)
	org.Put("/organizations/update", handler.UpdateOrganization)	
	org.Delete("/organizations/delete", handler.DeleteOrganization)
	org.Get("/organizations/get", handler.GetOrganization)
	org.Get("/organizations/list", handler.ListOrganizations)

	org.Get("/settings/get", handler.GetSettings)
	org.Put("/settings/update", handler.UpdateSettings)
}
