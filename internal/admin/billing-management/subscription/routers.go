package subscription

import (
	"github.com/gofiber/fiber/v2"

	// rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(router fiber.Router, handler *SubscriptionHandler, auditLogger security_management.AuditLogger) {
	route := router.Group("/plans", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", rbacmiddleware.RBACMiddleware("plan", "create", nil), handler.CreatePlan)
	route.Get("/", rbacmiddleware.RBACMiddleware("plan", "read", nil), handler.ListPlans)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("plan", "read", nil), handler.GetPlan)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("plan", "update", nil), handler.UpdatePlan)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("plan", "delete", nil), handler.DeletePlan)

	route = router.Group("/usages", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", rbacmiddleware.RBACMiddleware("usage", "create", nil), handler.CreateUsage)
	route.Get("/", rbacmiddleware.RBACMiddleware("usage", "read", nil), handler.ListUsage)

	route = router.Group("/subscriptions", auditmiddleware.AuditLoggerMiddleware(auditLogger))
	route.Post("/", rbacmiddleware.RBACMiddleware("subscription", "create", nil), handler.CreateSubscription)
	route.Get("/", rbacmiddleware.RBACMiddleware("subscription", "read", nil), handler.ListSubscriptions)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("subscription", "read", nil), handler.GetSubscription)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("subscription", "update", nil), handler.UpdateSubscription)
	route.Patch("/:id", rbacmiddleware.RBACMiddleware("subscription", "update", nil), handler.PatchSubscription)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("subscription", "delete", nil), handler.DeleteSubscription)

	route.Post("/:id/change-plan", rbacmiddleware.RBACMiddleware("subscription", "change-plan", nil), handler.ChangePlanSubscription)
	route.Post("/:id/cancel-now", rbacmiddleware.RBACMiddleware("subscription", "cancel", nil), handler.CancelSubscriptionNow)
	route.Post("/:id/resume", rbacmiddleware.RBACMiddleware("subscription", "resume", nil), handler.ResumeSubscription)
	route.Post("/:id/upgrade-now", rbacmiddleware.RBACMiddleware("subscription", "upgrade", nil), handler.UpgradeNowSubscription)

	// Unified plugin management endpoints
	pluginRoutes := router.Group("/plugins/subscription")
	pluginRoutes.Get("/", rbacmiddleware.RBACMiddleware("subscription-plugin", "read", nil), handler.ListSubscriptionPlugins)
	pluginRoutes.Get(":name", rbacmiddleware.RBACMiddleware("subscription-plugin", "read", nil), handler.GetSubscriptionPlugin)
	pluginRoutes.Post(":name/configure", rbacmiddleware.RBACMiddleware("subscription-plugin", "update", nil), handler.ConfigureSubscriptionPlugin)
	pluginRoutes.Post(":name/disable", rbacmiddleware.RBACMiddleware("subscription-plugin", "update", nil), handler.DisableSubscriptionPlugin)
}
