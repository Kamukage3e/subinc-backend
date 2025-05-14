package discount

import (

	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterDiscountRoutes(router fiber.Router, handler *DiscountHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	// audit := auditmiddleware.AuditLoggerMiddleware(auditLogger)

	discount := router.Group("/discounts", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	discount.Post("/create", handler.CreateDiscount)
	discount.Put("/update", handler.UpdateDiscount)
	discount.Delete("/delete", handler.DeleteDiscount)
	discount.Get("/get", handler.GetDiscount)
	discount.Get("/code", handler.GetDiscountByCode)
	discount.Get("/list", handler.ListDiscounts)

	coupon := discount.Group("/coupons", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	coupon.Post("/create", handler.CreateCoupon)
	coupon.Put("/update", handler.UpdateCoupon)
	coupon.Delete("/delete", handler.DeleteCoupon)
	coupon.Get("/get", handler.GetCoupon)
	coupon.Get("/code", handler.GetCouponByCode)
	coupon.Get("/list", handler.ListCoupons)
	coupon.Post("/redeem", handler.RedeemCoupon)

	credit := discount.Group("/credits", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	credit.Post("/create", handler.CreateCredit)
	credit.Put("/update", handler.UpdateCredit)
	credit.Patch("/patch", handler.PatchCredit)
	credit.Delete("/delete", handler.DeleteCredit)
	credit.Get("/get", handler.GetCredit)
	credit.Get("/list", handler.ListCredits)
	credit.Post("/apply", handler.ApplyCreditsToInvoice)
}
