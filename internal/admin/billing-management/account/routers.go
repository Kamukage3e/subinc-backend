package account

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

// accountScopeExtractor extracts account-specific identifiers for rate limiting
func billingScopeExtractor(c *fiber.Ctx) (string, string) {
	return "account", c.Get("X-Account-ID")
}

func RegisterRoutes(r fiber.Router, handler *AccountHandler, jwtCfg string, rateLimitService security_management.RateLimitService) {
	route := r.Group("/accounts",
		security_management.OIDCMiddleware(jwtCfg),
		security_management.NewRateLimitMiddleware(rateLimitService, billingScopeExtractor),
	)
	route.Post("/", rbacmiddleware.RBACMiddleware("account", "create", nil), handler.CreateAccount)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("account", "read", nil), handler.GetAccount)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("account", "update", nil), handler.UpdateAccount)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("account", "delete", nil), handler.DeleteAccount)
	route.Get("/", rbacmiddleware.RBACMiddleware("account", "read", nil), handler.ListAccounts)
	route.Post("/:id/action", rbacmiddleware.RBACMiddleware("account", "action", nil), handler.PerformAccountAction)
}
