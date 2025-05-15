package discount

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(router fiber.Router, handler *DiscountHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	// audit := auditmiddleware.AuditLoggerMiddleware(auditLogger)

	route := router.Group("/discounts", rbacmiddleware.RBACMiddleware("discount", "create", nil))
	route.Post("/", rbacmiddleware.RBACMiddleware("discount", "create", nil), handler.CreateDiscount)
	route.Get("/", rbacmiddleware.RBACMiddleware("discount", "read", nil), handler.ListDiscounts)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("discount", "read", nil), handler.GetDiscount)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("discount", "update", nil), handler.UpdateDiscount)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("discount", "delete", nil), handler.DeleteDiscount)
	route.Get("/code/:code", rbacmiddleware.RBACMiddleware("discount", "read", nil), handler.GetDiscountByCode)

	route.Post("/coupons", rbacmiddleware.RBACMiddleware("coupon", "create", nil), handler.CreateCoupon)
	route.Get("/coupons", rbacmiddleware.RBACMiddleware("coupon", "read", nil), handler.ListCoupons)
	route.Get("/coupons/:id", rbacmiddleware.RBACMiddleware("coupon", "read", nil), handler.GetCoupon)
	route.Put("/coupons/:id", rbacmiddleware.RBACMiddleware("coupon", "update", nil), handler.UpdateCoupon)
	route.Delete("/coupons/:id", rbacmiddleware.RBACMiddleware("coupon", "delete", nil), handler.DeleteCoupon)
	route.Get("/coupons/code/:code", rbacmiddleware.RBACMiddleware("coupon", "read", nil), handler.GetCouponByCode)
	route.Post("/coupons/:id/redeem", rbacmiddleware.RBACMiddleware("coupon", "redeem", nil), handler.RedeemCoupon)

	route.Post("/credits", rbacmiddleware.RBACMiddleware("credit", "create", nil), handler.CreateCredit)
	route.Get("/credits", rbacmiddleware.RBACMiddleware("credit", "read", nil), handler.ListCredits)
	route.Get("/credits/:id", rbacmiddleware.RBACMiddleware("credit", "read", nil), handler.GetCredit)
	route.Put("/credits/:id", rbacmiddleware.RBACMiddleware("credit", "update", nil), handler.UpdateCredit)
	route.Patch("/credits/:id", rbacmiddleware.RBACMiddleware("credit", "update", nil), handler.PatchCredit)
	route.Delete("/credits/:id", rbacmiddleware.RBACMiddleware("credit", "delete", nil), handler.DeleteCredit)
	route.Post("/credits/:id/apply", rbacmiddleware.RBACMiddleware("credit", "apply", nil), handler.ApplyCreditsToInvoice)
}
