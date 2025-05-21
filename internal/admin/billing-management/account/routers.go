package account

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(r fiber.Router, handler *AccountHandler, jwtCfg string, tenantStore tenant_management.TenantService) {
	// Create account route group with authentication middleware
	route := r.Group("/accounts",
		security_management.OIDCMiddleware(jwtCfg),
	)

	// Apply tenant middleware to all routes that require tenant verification
	tenantProtectedRoutes := route.Group("/",
		TenantMiddleware(tenantStore),
	)

	// The create account endpoint doesn't require tenant validation as it might create a new tenant
	route.Post("/", rbacmiddleware.RBACMiddleware("account", "create", nil), handler.CreateAccount)

	// All other routes require tenant validation
	tenantProtectedRoutes.Get("/:id", rbacmiddleware.RBACMiddleware("account", "read", nil), handler.GetAccount)
	tenantProtectedRoutes.Put("/:id", rbacmiddleware.RBACMiddleware("account", "update", nil), handler.UpdateAccount)
	tenantProtectedRoutes.Delete("/:id", rbacmiddleware.RBACMiddleware("account", "delete", nil), handler.DeleteAccount)
	tenantProtectedRoutes.Get("/", rbacmiddleware.RBACMiddleware("account", "read", nil), handler.ListAccounts)
	tenantProtectedRoutes.Post("/:id/action", rbacmiddleware.RBACMiddleware("account", "action", nil), handler.PerformAccountAction)
}
