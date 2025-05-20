package fee

import (
	"github.com/gofiber/fiber/v2"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(router fiber.Router, handler *FeeHandler) {
	route := router.Group("/fees", rbacmiddleware.RBACMiddleware("fee", "create", nil))
	route.Post("/", rbacmiddleware.RBACMiddleware("fee", "create", nil), handler.CreateFee)
	route.Get("/", rbacmiddleware.RBACMiddleware("fee", "read", nil), handler.ListFees)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("fee", "read", nil), handler.GetFee)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("fee", "update", nil), handler.UpdateFee)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("fee", "delete", nil), handler.DeleteFee)

	// Unified plugin management endpoints
	pluginRoutes := router.Group("/plugins/fee")
	pluginRoutes.Get("/", rbacmiddleware.RBACMiddleware("fee-plugin", "read", nil), handler.ListFeePlugins)
	pluginRoutes.Get(":name", rbacmiddleware.RBACMiddleware("fee-plugin", "read", nil), handler.GetFeePlugin)
	pluginRoutes.Post(":name/register", rbacmiddleware.RBACMiddleware("fee-plugin", "create", nil), handler.RegisterFeePlugin)
	pluginRoutes.Post(":name/unregister", rbacmiddleware.RBACMiddleware("fee-plugin", "delete", nil), handler.UnregisterFeePlugin)
	pluginRoutes.Post(":name/configure", rbacmiddleware.RBACMiddleware("fee-plugin", "update", nil), handler.ConfigureFeePlugin)
	pluginRoutes.Post(":name/disable", rbacmiddleware.RBACMiddleware("fee-plugin", "update", nil), handler.DisableFeePlugin)
}
