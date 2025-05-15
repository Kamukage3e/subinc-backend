package subscription

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterRoutes(router fiber.Router, handler *SubscriptionHandler, auditLogger security_management.AuditLogger) {
	route := router.Group("/plans", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", handler.CreatePlan)
	route.Get("/", handler.ListPlans)
	route.Get("/:id", handler.GetPlan)
	route.Put("/:id", handler.UpdatePlan)
	route.Delete("/:id", handler.DeletePlan)

	route = router.Group("/usages", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", handler.CreateUsage)
	route.Get("/", handler.ListUsage)

	route = router.Group("/subscriptions", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", handler.CreateSubscription)
	route.Get("/", handler.ListSubscriptions)
	route.Get("/:id", handler.GetSubscription)
	route.Put("/:id", handler.UpdateSubscription)
	route.Patch("/:id", handler.PatchSubscription)
	route.Delete("/:id", handler.DeleteSubscription)

	route.Post("/:id/change-plan", handler.ChangePlanSubscription)
	route.Post("/:id/cancel-now", handler.CancelSubscriptionNow)
	route.Post("/:id/resume", handler.ResumeSubscription)
	route.Post("/:id/upgrade-now", handler.UpgradeNowSubscription)
}
