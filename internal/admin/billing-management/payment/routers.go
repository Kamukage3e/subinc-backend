package payment

import (
	"github.com/gofiber/fiber/v2"


	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func paymentScopeExtractor(c *fiber.Ctx) (string, string) {
	return "payment", c.Get("X-Payment-ID")
}

// RegisterPaymentRoutes registers payment related routes
func RegisterRoutes(router fiber.Router, handler *PaymentHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/payments",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, paymentScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)

	// Payment endpoints
	route.Post("/", rbacmiddleware.RBACMiddleware("payment", "create", nil), handler.CreatePayment)
	route.Get("/", rbacmiddleware.RBACMiddleware("payment", "read", nil), handler.ListPayments)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("payment", "read", nil), handler.GetPayment)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("payment", "update", nil), handler.UpdatePayment)
	route.Delete("/:id/refund", rbacmiddleware.RBACMiddleware("payment", "refund", nil), handler.DeleteRefund)
	route.Get("/:id/status", rbacmiddleware.RBACMiddleware("payment", "read", nil), handler.GetPaymentStatus)

	// Payment method endpoints
	route.Post("/payment-methods", rbacmiddleware.RBACMiddleware("payment-method", "create", nil), handler.CreatePaymentMethod)
	route.Get("/payment-methods", rbacmiddleware.RBACMiddleware("payment-method", "read", nil), handler.ListPaymentMethods)
	route.Get("/payment-methods/:id", rbacmiddleware.RBACMiddleware("payment-method", "read", nil), handler.GetPaymentMethod)
	route.Put("/payment-methods/:id", rbacmiddleware.RBACMiddleware("payment-method", "update", nil), handler.UpdatePaymentMethod)
	route.Patch("/payment-methods/:id", rbacmiddleware.RBACMiddleware("payment-method", "update", nil), handler.PatchPaymentMethod)
	route.Delete("/payment-methods/:id", rbacmiddleware.RBACMiddleware("payment-method", "delete", nil), handler.DeletePaymentMethod)

	// Refund endpoints
	route.Post("/refunds", rbacmiddleware.RBACMiddleware("refund", "create", nil), handler.CreateRefund)
	route.Get("/refunds", rbacmiddleware.RBACMiddleware("refund", "read", nil), handler.ListRefunds)
	route.Get("/refunds/:id", rbacmiddleware.RBACMiddleware("refund", "read", nil), handler.GetRefund)
	route.Put("/refunds/:id", rbacmiddleware.RBACMiddleware("refund", "update", nil), handler.UpdateRefund)
	route.Delete("/refunds/:id", rbacmiddleware.RBACMiddleware("refund", "delete", nil), handler.DeleteRefund)
	route.Post("/refunds/:id/manual", rbacmiddleware.RBACMiddleware("refund", "update", nil), handler.CreateManualRefund)

	// Dispute endpoints
	route.Post("/disputes", rbacmiddleware.RBACMiddleware("dispute", "create", nil), handler.CreateDispute)
	route.Get("/disputes", rbacmiddleware.RBACMiddleware("dispute", "read", nil), handler.ListDisputes)
	route.Get("/disputes/:id", rbacmiddleware.RBACMiddleware("dispute", "read", nil), handler.GetDispute)
	route.Put("/disputes/:id", rbacmiddleware.RBACMiddleware("dispute", "update", nil), handler.UpdateDispute)
	route.Delete("/disputes/:id", rbacmiddleware.RBACMiddleware("dispute", "delete", nil), handler.DeleteDispute)

	route.Post("/disputes/:id/evidence", rbacmiddleware.RBACMiddleware("evidence", "create", nil), handler.CreateEvidence)
	route.Get("/disputes/:id/evidence", rbacmiddleware.RBACMiddleware("evidence", "read", nil), handler.ListEvidence)
	route.Get("/disputes/evidence/:evidence_id", rbacmiddleware.RBACMiddleware("evidence", "read", nil), handler.GetEvidence)
	route.Put("/disputes/evidence/:evidence_id", rbacmiddleware.RBACMiddleware("evidence", "update", nil), handler.UpdateEvidence)
	route.Delete("/disputes/evidence/:evidence_id", rbacmiddleware.RBACMiddleware("evidence", "delete", nil), handler.DeleteEvidence)

	// Plugin management routes
	pluginRoutes := router.Group("/payments/plugins")
	pluginRoutes.Get("/", rbacmiddleware.RBACMiddleware("payment-plugin", "read", nil), handler.ListPaymentPlugins)
	pluginRoutes.Get(":name", rbacmiddleware.RBACMiddleware("payment-plugin", "read", nil), handler.GetPaymentPlugin)
	pluginRoutes.Post(":name/configure", rbacmiddleware.RBACMiddleware("payment-plugin", "update", nil), handler.ConfigurePaymentPlugin)
	pluginRoutes.Post(":name/disable", rbacmiddleware.RBACMiddleware("payment-plugin", "update", nil), handler.DisablePaymentPlugin)
}
