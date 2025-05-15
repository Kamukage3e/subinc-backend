package account

import (
	"github.com/gofiber/fiber/v2"

	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterRoutes(router fiber.Router, handler *AccountHandler, auditLogger security_management.AuditLogger) {
	route := router.Group("/accounts", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", rbac_management.RBACMiddleware("account", "create", nil), handler.CreateAccount)
	route.Get("/", rbac_management.RBACMiddleware("account", "read", nil), handler.ListAccounts)
	route.Get("/:id", rbac_management.RBACMiddleware("account", "read", nil), handler.GetAccount)
	route.Put("/:id", rbac_management.RBACMiddleware("account", "update", nil), handler.UpdateAccount)
	route.Post("/:id/action", rbac_management.RBACMiddleware("account", "action", nil), handler.PerformAccountAction)
}
