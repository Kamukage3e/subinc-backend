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
func RegisterPaymentRoutes(router fiber.Router, handler *PaymentHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	payment := router.Group(
		"/payments",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, paymentScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)

	// Payment endpoints
	payment.Post("/create", handler.CreatePayment)
	payment.Post("/refund", handler.RefundPayment)
	payment.Get("/status", handler.GetPaymentStatus)
	payment.Put("/update", handler.UpdatePayment)
	payment.Get("/get", handler.GetPayment)
	payment.Get("/list", handler.ListPayments)
	// Payment method endpoints
	methods := payment.Group("/methods", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	methods.Post("/create", handler.CreatePaymentMethod)
	methods.Put("/update", handler.UpdatePaymentMethod)
	methods.Patch("/patch", handler.PatchPaymentMethod)
	methods.Delete("/delete", handler.DeletePaymentMethod)
	methods.Get("/get", handler.GetPaymentMethod)
	methods.Get("/list", handler.ListPaymentMethods)

	// Refund endpoints
	refunds := payment.Group("/refunds", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	refunds.Post("/create", handler.CreateRefund)
	refunds.Put("/update", handler.UpdateRefund)
	refunds.Delete("/delete", handler.DeleteRefund)
	refunds.Get("/get", handler.GetRefund)
	refunds.Get("/list", handler.ListRefunds)


}
