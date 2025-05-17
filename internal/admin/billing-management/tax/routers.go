package tax

import (
	"github.com/gofiber/fiber/v2"

	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(router fiber.Router, handler *TaxHandler, jwtSecret string) {
	route := router.Group(
		"/tax-info",
		security_management.OIDCMiddleware(jwtSecret),
		rbac_management.RBACMiddleware("tax", "read", nil),
	)

	route = router.Group("/tax")

	route.Post("/", rbac_management.RBACMiddleware("tax", "create", nil), handler.SetTaxInfo)
	route.Get("/", handler.GetTaxInfo)

	// Plugin management routes (hot-pluggable tax calculation)
	pluginRoutes := router.Group("/tax/plugins")
	pluginRoutes.Get("/", rbacmiddleware.RBACMiddleware("tax-plugin", "read", nil), handler.ListTaxPlugins)
	pluginRoutes.Get(":name", rbacmiddleware.RBACMiddleware("tax-plugin", "read", nil), handler.GetTaxPlugin)
	pluginRoutes.Post(":name/configure", rbacmiddleware.RBACMiddleware("tax-plugin", "update", nil), handler.ConfigureTaxPlugin)
	pluginRoutes.Post(":name/disable", rbacmiddleware.RBACMiddleware("tax-plugin", "update", nil), handler.DisableTaxPlugin)
}
