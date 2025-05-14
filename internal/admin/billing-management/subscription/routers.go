package subscription

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func RegisterSubscriptionRoutes(router fiber.Router, handler *SubscriptionHandler, auditLogger security_management.AuditLogger) {
	subscriptionRouter := router.Group("/subscriptions", auditmiddleware.AuditLoggerMiddleware(auditLogger))

	subscriptionRouter.Post("/plans/create", handler.CreatePlan)
	subscriptionRouter.Put("/plans/update", handler.UpdatePlan)
	subscriptionRouter.Get("/plans/get", handler.GetPlan)
	subscriptionRouter.Get("/plans/list", handler.ListPlans)
	subscriptionRouter.Delete("/plans/delete", handler.DeletePlan)

	subscriptionRouter.Post("/usage/create", handler.CreateUsage)
	subscriptionRouter.Get("/usage/list", handler.ListUsage)

	subscriptionRouter.Post("/subscription/create", handler.CreateSubscription)
	subscriptionRouter.Put("/subscription/update", handler.UpdateSubscription)
	subscriptionRouter.Patch("/subscription/patch", handler.PatchSubscription)
	subscriptionRouter.Delete("/subscription/delete", handler.DeleteSubscription)
	subscriptionRouter.Get("/subscription/get", handler.GetSubscription)
	subscriptionRouter.Get("/subscription/list", handler.ListSubscriptions)
	subscriptionRouter.Post("/subscription/change-plan", handler.ChangePlanSubscription)
	subscriptionRouter.Post("/subscription/cancel", handler.CancelSubscriptionNow)
	subscriptionRouter.Post("/subscription/resume", handler.ResumeSubscription)
	subscriptionRouter.Post("/subscription/upgrade-now", handler.UpgradeNowSubscription)
}
