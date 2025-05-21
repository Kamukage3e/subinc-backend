package billing_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func RegisterRoutes(router fiber.Router, handler *BillingAdminHandler, jwtSecret string) {
	// Validate required parameters
	if router == nil || handler == nil {
		logger.LogError("RegisterRoutes: router or handler is nil")
		return
	}

	// Create base route with authentication
	route := router.Group(
		"/billing-management",
		security_management.OIDCMiddleware(jwtSecret),
	)

	// Apply account isolation middleware to all protected billing routes
	// This ensures tenant and account validation on all operations
	billingRoute := route.Group(
		"/",
		AccountIsolationMiddleware(),
	)

	// Standard billing routes
	billingRoute.Get("/accounts/invoice-preview", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.GetInvoicePreview)

	billingRoute.Get("/invoices", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.ListInvoices)
	billingRoute.Get("/invoices/:id", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.GetInvoice)
	billingRoute.Post("/invoices", rbacmiddleware.RBACMiddleware("invoice", "create", nil), handler.CreateInvoice)
	billingRoute.Put("/invoices/:id", rbacmiddleware.RBACMiddleware("invoice", "update", nil), handler.UpdateInvoice)
	billingRoute.Delete("/invoices/:id", rbacmiddleware.RBACMiddleware("invoice", "delete", nil), handler.DeleteInvoice)

	billingRoute.Get("/invoices/:id/pdf", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.DownloadInvoicePDF)
	billingRoute.Post("/invoices/:id/apply-credits", rbacmiddleware.RBACMiddleware("invoice", "apply-credits", nil), handler.ApplyCreditsToInvoice)
	billingRoute.Post("/invoices/:id/with-fees-tax", rbacmiddleware.RBACMiddleware("invoice", "create", nil), handler.CreateInvoiceWithFeesAndTax)
	billingRoute.Post("/invoices/:id/manual-adjustment", rbacmiddleware.RBACMiddleware("invoice", "manual-adjustment", nil), handler.CreateManualAdjustment)

	billingRoute.Post("/webhook-events", rbacmiddleware.RBACMiddleware("webhook-event", "create", nil), handler.CreateWebhookEvent)
	billingRoute.Get("/webhook-events", rbacmiddleware.RBACMiddleware("webhook-event", "read", nil), handler.ListWebhookEvents)
	billingRoute.Get("/webhook-events/:id", rbacmiddleware.RBACMiddleware("webhook-event", "read", nil), handler.GetWebhookEvent)
	billingRoute.Put("/webhook-events/:id", rbacmiddleware.RBACMiddleware("webhook-event", "update", nil), handler.UpdateWebhookEvent)
	billingRoute.Delete("/webhook-events/:id", rbacmiddleware.RBACMiddleware("webhook-event", "delete", nil), handler.DeleteWebhookEvent)

	billingRoute.Post("/invoice-adjustments", rbacmiddleware.RBACMiddleware("invoice-adjustment", "create", nil), handler.CreateInvoiceAdjustment)
	billingRoute.Get("/invoice-adjustments", rbacmiddleware.RBACMiddleware("invoice-adjustment", "read", nil), handler.ListInvoiceAdjustments)
	billingRoute.Get("/invoice-adjustments/:id", rbacmiddleware.RBACMiddleware("invoice-adjustment", "read", nil), handler.GetInvoiceAdjustment)
	billingRoute.Put("/invoice-adjustments/:id", rbacmiddleware.RBACMiddleware("invoice-adjustment", "update", nil), handler.UpdateInvoiceAdjustment)
	billingRoute.Delete("/invoice-adjustments/:id", rbacmiddleware.RBACMiddleware("invoice-adjustment", "delete", nil), handler.DeleteInvoiceAdjustment)

	billingRoute.Get("/reports/revenue", rbacmiddleware.RBACMiddleware("report", "read", nil), handler.GetRevenueReport)
	billingRoute.Get("/reports/accounts-receivable", rbacmiddleware.RBACMiddleware("report", "read", nil), handler.GetARReport)
	billingRoute.Get("/reports/churn", rbacmiddleware.RBACMiddleware("report", "read", nil), handler.GetChurnReport)

	billingRoute.Get("/billing/config", rbacmiddleware.RBACMiddleware("billing-config", "read", nil), handler.GetBillingConfig)
	billingRoute.Put("/billing/config", rbacmiddleware.RBACMiddleware("billing-config", "update", nil), handler.SetBillingConfig)

	billingRoute.Post("/webhook-subscriptions", rbacmiddleware.RBACMiddleware("webhook-subscription", "create", nil), handler.CreateWebhookSubscription)
	billingRoute.Get("/webhook-subscriptions", rbacmiddleware.RBACMiddleware("webhook-subscription", "read", nil), handler.ListWebhookSubscriptions)
	billingRoute.Get("/webhook-subscriptions/:id", rbacmiddleware.RBACMiddleware("webhook-subscription", "read", nil), handler.GetWebhookSubscription)
	billingRoute.Put("/webhook-subscriptions/:id", rbacmiddleware.RBACMiddleware("webhook-subscription", "update", nil), handler.UpdateWebhookSubscription)
	billingRoute.Delete("/webhook-subscriptions/:id", rbacmiddleware.RBACMiddleware("webhook-subscription", "delete", nil), handler.DeleteWebhookSubscription)
	billingRoute.Post("/webhook-subscriptions/:id/test", rbacmiddleware.RBACMiddleware("webhook-subscription", "update", nil), handler.TestWebhookSubscription)
	billingRoute.Get("/webhook-subscriptions/:id/logs", rbacmiddleware.RBACMiddleware("webhook-subscription", "read", nil), handler.GetWebhookDeliveryLogs)
	billingRoute.Post("/webhook-deliveries/:id/retry", rbacmiddleware.RBACMiddleware("webhook-subscription", "update", nil), handler.RetryWebhookDelivery)

	billingRoute.Post("/tenant-currency", rbacmiddleware.RBACMiddleware("tenant-currency", "update", nil), handler.SetTenantCurrency)
	billingRoute.Get("/tenant-currency", rbacmiddleware.RBACMiddleware("tenant-currency", "read", nil), handler.GetTenantCurrency)

	// Dunning management routes
	dunningRoutes := billingRoute.Group("/dunning")
	dunningRoutes.Get("/config", rbacmiddleware.RBACMiddleware("dunning", "read", nil), handler.GetDunningConfig)
	dunningRoutes.Post("/config", rbacmiddleware.RBACMiddleware("dunning", "update", nil), handler.UpdateDunningConfig)
	dunningRoutes.Post("/invoices/:id/retry", rbacmiddleware.RBACMiddleware("dunning", "update", nil), handler.ManualRetryDunning)
	dunningRoutes.Get("/invoices/:id/events", rbacmiddleware.RBACMiddleware("dunning", "read", nil), handler.GetDunningEvents)
	dunningRoutes.Get("/dashboard", rbacmiddleware.RBACMiddleware("dunning", "read", nil), handler.GetDunningDashboard)

	// Unified plugin management endpoints
	pluginRoutes := billingRoute.Group("/plugins")
	pluginRoutes.Get(":type", rbacmiddleware.RBACMiddleware("plugin", "read", nil), handler.ListPlugins)
	pluginRoutes.Get(":type/:name", rbacmiddleware.RBACMiddleware("plugin", "read", nil), handler.GetPlugin)
	pluginRoutes.Post(":type/:name/configure", rbacmiddleware.RBACMiddleware("plugin", "update", nil), handler.ConfigurePlugin)
	pluginRoutes.Post(":type/:name/disable", rbacmiddleware.RBACMiddleware("plugin", "update", nil), handler.DisablePlugin)
	pluginRoutes.Post(":type/:name/register", rbacmiddleware.RBACMiddleware("plugin", "create", nil), handler.RegisterPlugin)
	pluginRoutes.Post(":type/:name/unregister", rbacmiddleware.RBACMiddleware("plugin", "delete", nil), handler.UnregisterPlugin)

	// Stripe webhooks are public endpoints, do not wrap them with security middleware
	route.Post("/stripe/webhook", handler.StripeWebhookHandler)
}
