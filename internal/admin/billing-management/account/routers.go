package account

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterRoutes(router fiber.Router, handler *AccountHandler, auditLogger security_management.AuditLogger) {
	route := router.Group("/accounts", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", handler.CreateAccount)
	route.Get("/", handler.ListAccounts)
	route.Get("/:id", handler.GetAccount)
	route.Put("/:id", handler.UpdateAccount)
	route.Post("/:id/action", handler.PerformAccountAction)
}
