package account

import (


	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"

)



func RegisterAccountRoutes(router fiber.Router, handler *AccountHandler, auditLogger security_management.AuditLogger) {
	accountRouter := router.Group("/accounts", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	accountRouter.Post("/create", handler.CreateAccount)
	accountRouter.Put("/update", handler.UpdateAccount)
	accountRouter.Get("/get", handler.GetAccount)
	accountRouter.Get("/list", handler.ListAccounts)
	accountRouter.Post("/action/perform", handler.PerformAccountAction)
}

