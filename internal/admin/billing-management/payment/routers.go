package payment

import (
	"github.com/gofiber/fiber/v2"

	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
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
	route.Post("/", rbac_management.RBACMiddleware("payment", "create", nil), handler.CreatePayment)
	route.Get("/", rbac_management.RBACMiddleware("payment", "read", nil), handler.ListPayments)
	route.Get("/:id", rbac_management.RBACMiddleware("payment", "read", nil), handler.GetPayment)
	route.Put("/:id", rbac_management.RBACMiddleware("payment", "update", nil), handler.UpdatePayment)
	route.Post("/:id/refund", rbac_management.RBACMiddleware("payment", "refund", nil), handler.RefundPayment)
	route.Get("/:id/status", rbac_management.RBACMiddleware("payment", "read", nil), handler.GetPaymentStatus)

	// Payment method endpoints
	route.Post("/payment-methods", rbac_management.RBACMiddleware("payment-method", "create", nil), handler.CreatePaymentMethod)
	route.Get("/payment-methods", rbac_management.RBACMiddleware("payment-method", "read", nil), handler.ListPaymentMethods)
	route.Get("/payment-methods/:id", rbac_management.RBACMiddleware("payment-method", "read", nil), handler.GetPaymentMethod)
	route.Put("/payment-methods/:id", rbac_management.RBACMiddleware("payment-method", "update", nil), handler.UpdatePaymentMethod)
	route.Patch("/payment-methods/:id", rbac_management.RBACMiddleware("payment-method", "update", nil), handler.PatchPaymentMethod)
	route.Delete("/payment-methods/:id", rbac_management.RBACMiddleware("payment-method", "delete", nil), handler.DeletePaymentMethod)

	// Refund endpoints
	route.Post("/refunds", rbac_management.RBACMiddleware("refund", "create", nil), handler.CreateRefund)
	route.Get("/refunds", rbac_management.RBACMiddleware("refund", "read", nil), handler.ListRefunds)
	route.Get("/refunds/:id", rbac_management.RBACMiddleware("refund", "read", nil), handler.GetRefund)
	route.Put("/refunds/:id", rbac_management.RBACMiddleware("refund", "update", nil), handler.UpdateRefund)
	route.Delete("/refunds/:id", rbac_management.RBACMiddleware("refund", "delete", nil), handler.DeleteRefund)

	// Dispute endpoints
	route.Post("/disputes", rbac_management.RBACMiddleware("dispute", "create", nil), handler.CreateDispute)
	route.Get("/disputes", rbac_management.RBACMiddleware("dispute", "read", nil), handler.ListDisputes)
	route.Get("/disputes/:id", rbac_management.RBACMiddleware("dispute", "read", nil), handler.GetDispute)
	route.Put("/disputes/:id", rbac_management.RBACMiddleware("dispute", "update", nil), handler.UpdateDispute)
	route.Delete("/disputes/:id", rbac_management.RBACMiddleware("dispute", "delete", nil), handler.DeleteDispute)

	route.Post("/disputes/:id/evidence", rbac_management.RBACMiddleware("evidence", "create", nil), handler.CreateEvidence)
	route.Get("/disputes/:id/evidence", rbac_management.RBACMiddleware("evidence", "read", nil), handler.ListEvidence)
	route.Get("/disputes/evidence/:evidence_id", rbac_management.RBACMiddleware("evidence", "read", nil), handler.GetEvidence)
	route.Put("/disputes/evidence/:evidence_id", rbac_management.RBACMiddleware("evidence", "update", nil), handler.UpdateEvidence)
	route.Delete("/disputes/evidence/:evidence_id", rbac_management.RBACMiddleware("evidence", "delete", nil), handler.DeleteEvidence)
}
