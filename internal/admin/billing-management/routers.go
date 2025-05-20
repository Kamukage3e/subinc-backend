package billing_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func billingScopeExtractor(c *fiber.Ctx) (string, string) {
	return "billing", c.Get("X-Billing-ID")
}

func RegisterRoutes(router fiber.Router, handler *BillingAdminHandler, jwtSecret string) {
	// Validate required parameters
	if router == nil || handler == nil {
		logger.LogError("RegisterRoutes: router or handler is nil")
		return
	}

	route := router.Group(
		"/billing-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, billingScopeExtractor),

	)

	// Register account routes

	// Standard billing routes
	route.Get("/accounts/invoice-preview", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.GetInvoicePreview)

	route.Get("/invoices", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.ListInvoices)
	route.Get("/invoices/:id", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.GetInvoice)
	route.Post("/invoices", rbacmiddleware.RBACMiddleware("invoice", "create", nil), handler.CreateInvoice)
	route.Put("/invoices/:id", rbacmiddleware.RBACMiddleware("invoice", "update", nil), handler.UpdateInvoice)
	route.Delete("/invoices/:id", rbacmiddleware.RBACMiddleware("invoice", "delete", nil), handler.DeleteInvoice)

	route.Get("/invoices/:id/pdf", rbacmiddleware.RBACMiddleware("invoice", "read", nil), handler.DownloadInvoicePDF)
	route.Post("/invoices/:id/apply-credits", rbacmiddleware.RBACMiddleware("invoice", "apply-credits", nil), handler.ApplyCreditsToInvoice)
	route.Post("/invoices/:id/with-fees-tax", rbacmiddleware.RBACMiddleware("invoice", "create", nil), handler.CreateInvoiceWithFeesAndTax)
	route.Post("/invoices/:id/manual-adjustment", rbacmiddleware.RBACMiddleware("invoice", "manual-adjustment", nil), handler.CreateManualAdjustment)

	route.Post("/webhook-events", rbacmiddleware.RBACMiddleware("webhook-event", "create", nil), handler.CreateWebhookEvent)
	route.Get("/webhook-events", rbacmiddleware.RBACMiddleware("webhook-event", "read", nil), handler.ListWebhookEvents)
	route.Get("/webhook-events/:id", rbacmiddleware.RBACMiddleware("webhook-event", "read", nil), handler.GetWebhookEvent)
	route.Put("/webhook-events/:id", rbacmiddleware.RBACMiddleware("webhook-event", "update", nil), handler.UpdateWebhookEvent)
	route.Delete("/webhook-events/:id", rbacmiddleware.RBACMiddleware("webhook-event", "delete", nil), handler.DeleteWebhookEvent)

	route.Post("/invoice-adjustments", rbacmiddleware.RBACMiddleware("invoice-adjustment", "create", nil), handler.CreateInvoiceAdjustment)
	route.Get("/invoice-adjustments", rbacmiddleware.RBACMiddleware("invoice-adjustment", "read", nil), handler.ListInvoiceAdjustments)
	route.Get("/invoice-adjustments/:id", rbacmiddleware.RBACMiddleware("invoice-adjustment", "read", nil), handler.GetInvoiceAdjustment)
	route.Put("/invoice-adjustments/:id", rbacmiddleware.RBACMiddleware("invoice-adjustment", "update", nil), handler.UpdateInvoiceAdjustment)
	route.Delete("/invoice-adjustments/:id", rbacmiddleware.RBACMiddleware("invoice-adjustment", "delete", nil), handler.DeleteInvoiceAdjustment)

	route.Get("/reports/revenue", rbacmiddleware.RBACMiddleware("report", "read", nil), handler.GetRevenueReport)
	route.Get("/reports/accounts-receivable", rbacmiddleware.RBACMiddleware("report", "read", nil), handler.GetARReport)
	route.Get("/reports/churn", rbacmiddleware.RBACMiddleware("report", "read", nil), handler.GetChurnReport)

	route.Get("/billing/config", rbacmiddleware.RBACMiddleware("billing-config", "read", nil), handler.GetBillingConfig)
	route.Put("/billing/config", rbacmiddleware.RBACMiddleware("billing-config", "update", nil), handler.SetBillingConfig)

	route.Post("/webhook-subscriptions", rbacmiddleware.RBACMiddleware("webhook-subscription", "create", nil), handler.CreateWebhookSubscription)
	route.Get("/webhook-subscriptions", rbacmiddleware.RBACMiddleware("webhook-subscription", "read", nil), handler.ListWebhookSubscriptions)
	route.Get("/webhook-subscriptions/:id", rbacmiddleware.RBACMiddleware("webhook-subscription", "read", nil), handler.GetWebhookSubscription)
	route.Put("/webhook-subscriptions/:id", rbacmiddleware.RBACMiddleware("webhook-subscription", "update", nil), handler.UpdateWebhookSubscription)
	route.Delete("/webhook-subscriptions/:id", rbacmiddleware.RBACMiddleware("webhook-subscription", "delete", nil), handler.DeleteWebhookSubscription)
	route.Post("/webhook-subscriptions/:id/test", rbacmiddleware.RBACMiddleware("webhook-subscription", "update", nil), handler.TestWebhookSubscription)
	route.Get("/webhook-subscriptions/:id/logs", rbacmiddleware.RBACMiddleware("webhook-subscription", "read", nil), handler.GetWebhookDeliveryLogs)
	route.Post("/webhook-deliveries/:id/retry", rbacmiddleware.RBACMiddleware("webhook-subscription", "update", nil), handler.RetryWebhookDelivery)

	route.Post("/tenant-currency", rbacmiddleware.RBACMiddleware("tenant-currency", "update", nil), handler.SetTenantCurrency)
	route.Get("/tenant-currency", rbacmiddleware.RBACMiddleware("tenant-currency", "read", nil), handler.GetTenantCurrency)

	// Dunning management routes
	dunningRoutes := route.Group("/dunning")
	dunningRoutes.Get("/config", rbacmiddleware.RBACMiddleware("dunning", "read", nil), handler.GetDunningConfig)
	dunningRoutes.Post("/config", rbacmiddleware.RBACMiddleware("dunning", "update", nil), handler.UpdateDunningConfig)
	dunningRoutes.Post("/invoices/:id/retry", rbacmiddleware.RBACMiddleware("dunning", "update", nil), handler.ManualRetryDunning)
	dunningRoutes.Get("/invoices/:id/events", rbacmiddleware.RBACMiddleware("dunning", "read", nil), handler.GetDunningEvents)
	dunningRoutes.Get("/dashboard", rbacmiddleware.RBACMiddleware("dunning", "read", nil), handler.GetDunningDashboard)

	// Unified plugin management endpoints
	pluginRoutes := route.Group("/plugins")
	pluginRoutes.Get(":type", rbacmiddleware.RBACMiddleware("plugin", "read", nil), handler.ListPlugins)
	pluginRoutes.Get(":type/:name", rbacmiddleware.RBACMiddleware("plugin", "read", nil), handler.GetPlugin)
	pluginRoutes.Post(":type/:name/configure", rbacmiddleware.RBACMiddleware("plugin", "update", nil), handler.ConfigurePlugin)
	pluginRoutes.Post(":type/:name/disable", rbacmiddleware.RBACMiddleware("plugin", "update", nil), handler.DisablePlugin)
	pluginRoutes.Post(":type/:name/register", rbacmiddleware.RBACMiddleware("plugin", "create", nil), handler.RegisterPlugin)
	pluginRoutes.Post(":type/:name/unregister", rbacmiddleware.RBACMiddleware("plugin", "delete", nil), handler.UnregisterPlugin)

	route.Post("/stripe/webhook", handler.StripeWebhookHandler) // Stripe webhooks are public, do not wrap
}
