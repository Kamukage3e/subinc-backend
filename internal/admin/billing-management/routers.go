package billing_management

import (
	"github.com/gofiber/fiber/v2"

	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func billingScopeExtractor(c *fiber.Ctx) (string, string) {
	return "billing", c.Get("X-Billing-ID")
}

func RegisterRoutes(router fiber.Router, handler *BillingAdminHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/billing-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, billingScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)

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
	route.Delete("/webhook-subscriptions/:id", rbacmiddleware.RBACMiddleware("webhook-subscription", "delete", nil), handler.DeleteWebhookSubscription)

	route.Post("/tenant-currency", rbacmiddleware.RBACMiddleware("tenant-currency", "update", nil), handler.SetTenantCurrency)
	route.Get("/tenant-currency", rbacmiddleware.RBACMiddleware("tenant-currency", "read", nil), handler.GetTenantCurrency)

	route.Post("/stripe/webhook", handler.StripeWebhookHandler) // Stripe webhooks are public, do not wrap
}
