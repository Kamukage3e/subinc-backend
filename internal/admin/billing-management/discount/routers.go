package discount

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterDiscountRoutes(router fiber.Router, handler *DiscountHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	audit := AuditLoggerMiddleware(auditLogger)

	discount := router.Group("/discounts")
	discount.Post("/create", audit, handler.CreateDiscount)
	discount.Put("/update", audit, handler.UpdateDiscount)
	discount.Delete("/delete", audit, handler.DeleteDiscount)
	discount.Get("/get", handler.GetDiscount)
	discount.Get("/code", handler.GetDiscountByCode)
	discount.Get("/list", handler.ListDiscounts)

	coupon := discount.Group("/coupons")
	coupon.Post("/create", audit, handler.CreateCoupon)
	coupon.Put("/update", audit, handler.UpdateCoupon)
	coupon.Delete("/delete", audit, handler.DeleteCoupon)
	coupon.Get("/get", handler.GetCoupon)
	coupon.Get("/code", handler.GetCouponByCode)
	coupon.Get("/list", handler.ListCoupons)
	coupon.Post("/redeem", audit, handler.RedeemCoupon)

	credit := discount.Group("/credits")
	credit.Post("/create", audit, handler.CreateCredit)
	credit.Put("/update", audit, handler.UpdateCredit)
	credit.Patch("/patch", audit, handler.PatchCredit)
	credit.Delete("/delete", audit, handler.DeleteCredit)
	credit.Get("/get", handler.GetCredit)
	credit.Get("/list", handler.ListCredits)
	credit.Post("/apply", audit, handler.ApplyCreditsToInvoice)
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
