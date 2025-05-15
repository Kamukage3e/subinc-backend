package tax

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterRoutes(router fiber.Router, handler *TaxHandler, auditLogger security_management.AuditLogger) {
	route := router.Group("/tax", auditmiddleware.AuditLoggerMiddleware(auditLogger))

	route.Post("/tax-info", handler.SetTaxInfo)
	route.Get("/tax-info/:tenant_id", handler.GetTaxInfo)

	route.Get("/plugins", handler.ListTaxPlugins)
	route.Put("/plugin/:tenant_id", handler.SetTaxPluginConfig)
	route.Get("/plugin/:tenant_id", handler.GetTaxPluginConfig)
	route.Post("/tax-plugin/list", handler.ListTaxPlugins)
}
