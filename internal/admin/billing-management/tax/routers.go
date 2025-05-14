package tax

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)



func RegisterTaxRoutes(router fiber.Router, handler *TaxHandler, auditLogger security_management.AuditLogger) {
	taxRouter := router.Group("/tax", auditmiddleware.AuditLoggerMiddleware(auditLogger))

	taxRouter.Post("/tax-info/set", handler.SetTaxInfo)
	taxRouter.Get("/tax-info/get", handler.GetTaxInfo)
	taxRouter.Post("/tax-plugin/list", handler.ListTaxPlugins)
	taxRouter.Post("/tax-plugin/set", handler.SetTaxPluginConfig)
}
