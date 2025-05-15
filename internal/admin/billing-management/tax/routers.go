package tax

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
    
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(router fiber.Router, handler *TaxHandler, auditLogger security_management.AuditLogger) {
	route := router.Group("/tax", auditmiddleware.AuditLoggerMiddleware(auditLogger))

	route.Post("/tax-info", rbacmiddleware.RBACMiddleware("tax", "create", nil), handler.SetTaxInfo)
	route.Get("/tax-info/:tenant_id", rbacmiddleware.RBACMiddleware("tax", "read", nil), handler.GetTaxInfo)

	route.Get("/plugins", rbacmiddleware.RBACMiddleware("tax", "read", nil), handler.ListTaxPlugins)
	route.Put("/plugin/:tenant_id", rbacmiddleware.RBACMiddleware("tax", "update", nil), handler.SetTaxPluginConfig)
	route.Get("/plugin/:tenant_id", rbacmiddleware.RBACMiddleware("tax", "read", nil), handler.GetTaxPluginConfig)
	route.Post("/tax-plugin/list", rbacmiddleware.RBACMiddleware("tax", "read", nil), handler.ListTaxPlugins)
}
