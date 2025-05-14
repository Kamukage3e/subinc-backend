package payment

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func paymentScopeExtractor(c *fiber.Ctx) (string, string) {
	return "payment", c.Get("X-Payment-ID")
}

// RegisterPaymentRoutes registers payment related routes
func RegisterPaymentRoutes(router fiber.Router, handler *PaymentHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	audit := AuditLoggerMiddleware(auditLogger)
	payment := router.Group(
		"/payments",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, paymentScopeExtractor),
	)

	// Payment endpoints
	payment.Post("/create", audit, handler.CreatePayment)
	payment.Post("/refund", audit, handler.RefundPayment)
	payment.Get("/status", handler.GetPaymentStatus)
	payment.Put("/update", audit, handler.UpdatePayment)
	payment.Get("/get", handler.GetPayment)
	payment.Get("/list", handler.ListPayments)
	// Payment method endpoints
	methods := payment.Group("/methods")
	methods.Post("/create", audit, handler.CreatePaymentMethod)
	methods.Put("/update", audit, handler.UpdatePaymentMethod)
	methods.Patch("/patch", audit, handler.PatchPaymentMethod)
	methods.Delete("/delete", audit, handler.DeletePaymentMethod)
	methods.Get("/get", handler.GetPaymentMethod)
	methods.Get("/list", handler.ListPaymentMethods)

	// Refund endpoints
	refunds := payment.Group("/refunds")
	refunds.Post("/create", audit, handler.CreateRefund)
	refunds.Put("/update", audit, handler.UpdateRefund)
	refunds.Delete("/delete", audit, handler.DeleteRefund)
	refunds.Get("/get", handler.GetRefund)
	refunds.Get("/list", handler.ListRefunds)


}

// AuditLoggerMiddleware logs all mutating requests for security and compliance.
func AuditLoggerMiddleware(auditLogger security_management.AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		ctx = context.WithValue(ctx, "auditLogger", auditLogger)
		c.SetUserContext(ctx)
		err := c.Next()

		method := c.Method()
		if method == fiber.MethodPost || method == fiber.MethodPut || method == fiber.MethodDelete || method == fiber.MethodPatch {
			route := c.Route().Path
			actorID := c.Get("X-Actor-ID")
			var details map[string]interface{}
			var targetID string
			if c.Body() != nil && len(c.Body()) > 0 {
				if err := json.Unmarshal(c.Body(), &details); err != nil {
					details = map[string]interface{}{"body": string(c.Body())}
				} else {
					if id, ok := details["id"].(string); ok {
						targetID = id
					} else if tid, ok := details["target_id"].(string); ok {
						targetID = tid
					} else if aid, ok := details["account_id"].(string); ok {
						targetID = aid
					}
				}
			} else {
				details = map[string]interface{}{}
			}
			auditLog := security_management.SecurityAuditLog{
				ID:        uuid.NewString(),
				ActorID:   actorID,
				Action:    route + ":" + method,
				TargetID:  targetID,
				Details:   auditutil.AuditDetails(details),
				CreatedAt: time.Now().UTC(),
			}
			_, _ = auditLogger.CreateSecurityAuditLog(ctx, auditLog)
		}
		return err
	}
}
