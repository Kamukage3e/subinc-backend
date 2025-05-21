package organization_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(router fiber.Router, handler *OrganizationHandler, jwtSecretName string) {
	route := router.Group(
		"/organizations",
		security_management.OIDCMiddleware(jwtSecretName),
	)

	route.Post("/", rbacmiddleware.RBACMiddleware("organization", "create", nil), handler.CreateOrganization)
	route.Get("/", rbacmiddleware.RBACMiddleware("organization", "read", nil), handler.ListOrganizations)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("organization", "read", nil), handler.GetOrganization)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("organization", "update", nil), handler.UpdateOrganization)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("organization", "delete", nil), handler.DeleteOrganization)
	route.Get("/:id/settings", rbacmiddleware.RBACMiddleware("organization-settings", "read", nil), handler.GetSettings)
	route.Put("/:id/settings", rbacmiddleware.RBACMiddleware("organization-settings", "update", nil), handler.UpdateSettings)
}
