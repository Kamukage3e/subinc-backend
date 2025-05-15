package discount

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterRoutes(router fiber.Router, handler *DiscountHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	// audit := auditmiddleware.AuditLoggerMiddleware(auditLogger)

	route := router.Group("/discounts", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", handler.CreateDiscount)
	route.Get("/", handler.ListDiscounts)
	route.Get("/:id", handler.GetDiscount)
	route.Put("/:id", handler.UpdateDiscount)
	route.Delete("/:id", handler.DeleteDiscount)
	route.Get("/code/:code", handler.GetDiscountByCode)

	route.Post("/coupons", handler.CreateCoupon)
	route.Get("/coupons", handler.ListCoupons)
	route.Get("/coupons/:id", handler.GetCoupon)
	route.Put("/coupons/:id", handler.UpdateCoupon)
	route.Delete("/coupons/:id", handler.DeleteCoupon)
	route.Get("/coupons/code/:code", handler.GetCouponByCode)
	route.Post("/coupons/:id/redeem", handler.RedeemCoupon)

	route.Post("/credits", handler.CreateCredit)
	route.Get("/credits", handler.ListCredits)
	route.Get("/credits/:id", handler.GetCredit)
	route.Put("/credits/:id", handler.UpdateCredit)
	route.Patch("/credits/:id", handler.PatchCredit)
	route.Delete("/credits/:id", handler.DeleteCredit)
	route.Post("/credits/:id/apply", handler.ApplyCreditsToInvoice)
}
