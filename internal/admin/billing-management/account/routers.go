package account

import (
	"github.com/gofiber/fiber/v2"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(r fiber.Router, handler *AccountHandler) {
	route := r.Group("/accounts")
	route.Post("/", rbacmiddleware.RBACMiddleware("account", "create", nil), handler.CreateAccount)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("account", "read", nil), handler.GetAccount)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("account", "update", nil), handler.UpdateAccount)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("account", "delete", nil), handler.DeleteAccount)
	route.Get("/", rbacmiddleware.RBACMiddleware("account", "read", nil), handler.ListAccounts)
	route.Post("/:id/action", rbacmiddleware.RBACMiddleware("account", "action", nil), handler.PerformAccountAction)

	// Unified plugin management endpoints
	pluginRoutes := r.Group("/plugins/account")
	pluginRoutes.Get("/", rbacmiddleware.RBACMiddleware("account-plugin", "read", nil), handler.ListAccountPlugins)
	pluginRoutes.Get(":name", rbacmiddleware.RBACMiddleware("account-plugin", "read", nil), handler.GetAccountPlugin)
	pluginRoutes.Post(":name/configure", rbacmiddleware.RBACMiddleware("account-plugin", "update", nil), handler.ConfigureAccountPlugin)
	pluginRoutes.Post(":name/disable", rbacmiddleware.RBACMiddleware("account-plugin", "update", nil), handler.DisableAccountPlugin)
}
