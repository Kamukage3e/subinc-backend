package payment

import (
	"github.com/gofiber/fiber/v2"

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
	route.Post("/", handler.CreatePayment)
	route.Get("/", handler.ListPayments)
	route.Get("/:id", handler.GetPayment)
	route.Put("/:id", handler.UpdatePayment)
	route.Post("/:id/refund", handler.RefundPayment)
	route.Get("/:id/status", handler.GetPaymentStatus)

	// Payment method endpoints
	route.Post("/payment-methods", handler.CreatePaymentMethod)
	route.Get("/payment-methods", handler.ListPaymentMethods)
	route.Get("/payment-methods/:id", handler.GetPaymentMethod)
	route.Put("/payment-methods/:id", handler.UpdatePaymentMethod)
	route.Patch("/payment-methods/:id", handler.PatchPaymentMethod)
	route.Delete("/payment-methods/:id", handler.DeletePaymentMethod)

	// Refund endpoints
	route.Post("/refunds", handler.CreateRefund)
	route.Get("/refunds", handler.ListRefunds)
	route.Get("/refunds/:id", handler.GetRefund)
	route.Put("/refunds/:id", handler.UpdateRefund)
	route.Delete("/refunds/:id", handler.DeleteRefund)

	// Dispute endpoints
	route.Post("/disputes", handler.CreateDispute)
	route.Get("/disputes", handler.ListDisputes)
	route.Get("/disputes/:id", handler.GetDispute)
	route.Put("/disputes/:id", handler.UpdateDispute)
	route.Delete("/disputes/:id", handler.DeleteDispute)

	route.Post("/disputes/:id/evidence", handler.CreateEvidence)
	route.Get("/disputes/:id/evidence", handler.ListEvidence)
	route.Get("/disputes/evidence/:evidence_id", handler.GetEvidence)
	route.Put("/disputes/evidence/:evidence_id", handler.UpdateEvidence)
	route.Delete("/disputes/evidence/:evidence_id", handler.DeleteEvidence)
}
