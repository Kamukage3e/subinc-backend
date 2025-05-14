package billing_management

import (
	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func billingScopeExtractor(c *fiber.Ctx) (string, string) {
	return "billing", c.Get("X-Billing-ID")
}

func RegisterAdminBillingRoutes(router fiber.Router, handler *BillingAdminHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	billing := router.Group(
		"/billing-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, billingScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	// audit := auditmiddleware.AuditLoggerMiddleware(auditLogger)

	// Other non-payment routes
	billing.Get("/accounts/invoice-preview", handler.GetInvoicePreview)

	billing.Post("/invoices/create", handler.CreateInvoice)
	billing.Put("/invoices/update", handler.UpdateInvoice)
	billing.Get("/invoices/get", handler.GetInvoice)
	billing.Get("/invoices/list", handler.ListInvoices)
	billing.Post("/invoices/pdf/download", handler.DownloadInvoicePDF)

	billing.Post("/webhook-events/create", handler.CreateWebhookEvent)
	billing.Put("/webhook-events/update", handler.UpdateWebhookEvent)
	billing.Delete("/webhook-events/delete", handler.DeleteWebhookEvent)
	billing.Get("/webhook-events/get", handler.GetWebhookEvent)
	billing.Get("/webhook-events/list", handler.ListWebhookEvents)

	billing.Post("/invoice-adjustments/create", handler.CreateInvoiceAdjustment)
	billing.Put("/invoice-adjustments/update", handler.UpdateInvoiceAdjustment)
	billing.Delete("/invoice-adjustments/delete", handler.DeleteInvoiceAdjustment)
	billing.Get("/invoice-adjustments/get", handler.GetInvoiceAdjustment)
	billing.Get("/invoice-adjustments/list", handler.ListInvoiceAdjustments)
	billing.Post("/invoices/apply-credits", handler.ApplyCreditsToInvoice)
	billing.Post("/invoices/with-fees-tax/create", handler.CreateInvoiceWithFeesAndTax)

	billing.Get("/reports/revenue/get", handler.GetRevenueReport)
	billing.Get("/reports/accounts-receivable/get", handler.GetARReport)
	billing.Get("/reports/churn/get", handler.GetChurnReport)

	billing.Post("/manual-adjustment/create", handler.CreateManualAdjustment)

	billing.Get("/billing/config/get", handler.GetBillingConfig)
	billing.Post("/billing/config/set", handler.SetBillingConfig)

	billing.Post("/webhook-subscriptions/create", handler.CreateWebhookSubscription)
	billing.Get("/webhook-subscriptions/list", handler.ListWebhookSubscriptions)
	billing.Delete("/webhook-subscriptions/delete", handler.DeleteWebhookSubscription)

	billing.Post("/tenant-currency/set", handler.SetTenantCurrency)
	billing.Get("/tenant-currency/get", handler.GetTenantCurrency)

	billing.Post("/stripe/webhook", handler.StripeWebhookHandler)
}
