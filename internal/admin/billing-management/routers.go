package billing_management

import (
	"github.com/gofiber/fiber/v2"

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
	// audit := auditmiddleware.AuditLoggerMiddleware(auditLogger)

	// Other non-payment routes
	route.Get("/accounts/invoice-preview", handler.GetInvoicePreview)

	route.Get("/invoices", handler.ListInvoices)
	route.Get("/invoices/:id", handler.GetInvoice)
	route.Post("/invoices", handler.CreateInvoice)
	route.Put("/invoices/:id", handler.UpdateInvoice)
	route.Delete("/invoices/:id", handler.DeleteInvoice)

	route.Get("/invoices/:id/pdf", handler.DownloadInvoicePDF)
	route.Post("/invoices/:id/apply-credits", handler.ApplyCreditsToInvoice)
	route.Post("/invoices/:id/with-fees-tax", handler.CreateInvoiceWithFeesAndTax)
	route.Post("/invoices/:id/manual-adjustment", handler.CreateManualAdjustment)

	route.Post("/webhook-events", handler.CreateWebhookEvent)
	route.Get("/webhook-events", handler.ListWebhookEvents)
	route.Get("/webhook-events/:id", handler.GetWebhookEvent)
	route.Put("/webhook-events/:id", handler.UpdateWebhookEvent)
	route.Delete("/webhook-events/:id", handler.DeleteWebhookEvent)

	route.Post("/invoice-adjustments", handler.CreateInvoiceAdjustment)
	route.Get("/invoice-adjustments", handler.ListInvoiceAdjustments)
	route.Get("/invoice-adjustments/:id", handler.GetInvoiceAdjustment)
	route.Put("/invoice-adjustments/:id", handler.UpdateInvoiceAdjustment)
	route.Delete("/invoice-adjustments/:id", handler.DeleteInvoiceAdjustment)

	route.Get("/reports/revenue", handler.GetRevenueReport)
	route.Get("/reports/accounts-receivable", handler.GetARReport)
	route.Get("/reports/churn", handler.GetChurnReport)

	route.Get("/billing/config", handler.GetBillingConfig)
	route.Put("/billing/config", handler.SetBillingConfig)

	route.Post("/webhook-subscriptions", handler.CreateWebhookSubscription)
	route.Get("/webhook-subscriptions", handler.ListWebhookSubscriptions)
	route.Delete("/webhook-subscriptions/:id", handler.DeleteWebhookSubscription)

	route.Post("/tenant-currency", handler.SetTenantCurrency)
	route.Get("/tenant-currency", handler.GetTenantCurrency)

	route.Post("/stripe/webhook", handler.StripeWebhookHandler)
}
