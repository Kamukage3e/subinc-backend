package billing_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminBillingRoutes(router fiber.Router, handler *BillingAdminHandler) {
	billing := router.Group("/billing-management")

	billing.Post("/accounts", handler.CreateAccount)
	billing.Put("/accounts/:id", handler.UpdateAccount)
	billing.Get("/accounts/:id", handler.GetAccount)
	billing.Get("/accounts", handler.ListAccounts)

	billing.Post("/plans", handler.CreatePlan)
	billing.Put("/plans/:id", handler.UpdatePlan)
	billing.Get("/plans/:id", handler.GetPlan)
	billing.Get("/plans", handler.ListPlans)
	billing.Delete("/plans/:id", handler.DeletePlan)

	billing.Post("/usage", handler.CreateUsage)
	billing.Get("/usage", handler.ListUsage)

	billing.Post("/invoices", handler.CreateInvoice)
	billing.Put("/invoices/:id", handler.UpdateInvoice)
	billing.Get("/invoices/:id", handler.GetInvoice)
	billing.Get("/invoices", handler.ListInvoices)

	billing.Post("/payments", handler.CreatePayment)
	billing.Put("/payments/:id", handler.UpdatePayment)
	billing.Get("/payments/:id", handler.GetPayment)
	billing.Get("/payments", handler.ListPayments)

	billing.Post("/audit-logs", handler.CreateAuditLog)
	billing.Get("/audit-logs", handler.ListAuditLogs)
	billing.Get("/audit-logs/search", handler.SearchAuditLogs)

	billing.Post("/discounts", handler.CreateDiscount)
	billing.Put("/discounts/:id", handler.UpdateDiscount)
	billing.Delete("/discounts/:id", handler.DeleteDiscount)
	billing.Get("/discounts/:id", handler.GetDiscount)
	billing.Get("/discounts/code/:code", handler.GetDiscountByCode)
	billing.Get("/discounts", handler.ListDiscounts)

	billing.Post("/coupons", handler.CreateCoupon)
	billing.Put("/coupons/:id", handler.UpdateCoupon)
	billing.Delete("/coupons/:id", handler.DeleteCoupon)
	billing.Get("/coupons/:id", handler.GetCoupon)
	billing.Get("/coupons/code/:code", handler.GetCouponByCode)
	billing.Get("/coupons", handler.ListCoupons)

	billing.Post("/credits", handler.CreateCredit)
	billing.Put("/credits/:id", handler.UpdateCredit)
	billing.Patch("/credits/:id", handler.PatchCredit)
	billing.Delete("/credits/:id", handler.DeleteCredit)
	billing.Get("/credits/:id", handler.GetCredit)
	billing.Get("/credits", handler.ListCredits)

	billing.Post("/refunds", handler.CreateRefund)
	billing.Put("/refunds/:id", handler.UpdateRefund)
	billing.Delete("/refunds/:id", handler.DeleteRefund)
	billing.Get("/refunds/:id", handler.GetRefund)
	billing.Get("/refunds", handler.ListRefunds)

	billing.Post("/payment-methods", handler.CreatePaymentMethod)
	billing.Put("/payment-methods/:id", handler.UpdatePaymentMethod)
	billing.Patch("/payment-methods/:id", handler.PatchPaymentMethod)
	billing.Delete("/payment-methods/:id", handler.DeletePaymentMethod)
	billing.Get("/payment-methods/:id", handler.GetPaymentMethod)
	billing.Get("/payment-methods", handler.ListPaymentMethods)

	billing.Post("/subscriptions", handler.CreateSubscription)
	billing.Put("/subscriptions/:id", handler.UpdateSubscription)
	billing.Patch("/subscriptions/:id", handler.PatchSubscription)
	billing.Delete("/subscriptions/:id", handler.DeleteSubscription)
	billing.Get("/subscriptions/:id", handler.GetSubscription)
	billing.Get("/subscriptions", handler.ListSubscriptions)
	billing.Post("/subscriptions/:id/change-plan", handler.ChangePlanSubscription)
	billing.Post("/subscriptions/:id/cancel", handler.CancelSubscriptionNow)
	billing.Post("/subscriptions/:id/resume", handler.ResumeSubscription)
	billing.Post("/subscriptions/:id/upgrade-now", handler.UpgradeNowSubscription)

	billing.Post("/webhook-events", handler.CreateWebhookEvent)
	billing.Put("/webhook-events/:id", handler.UpdateWebhookEvent)
	billing.Delete("/webhook-events/:id", handler.DeleteWebhookEvent)
	billing.Get("/webhook-events/:id", handler.GetWebhookEvent)
	billing.Get("/webhook-events", handler.ListWebhookEvents)

	billing.Post("/invoice-adjustments", handler.CreateInvoiceAdjustment)
	billing.Put("/invoice-adjustments/:id", handler.UpdateInvoiceAdjustment)
	billing.Delete("/invoice-adjustments/:id", handler.DeleteInvoiceAdjustment)
	billing.Get("/invoice-adjustments/:id", handler.GetInvoiceAdjustment)
	billing.Get("/invoice-adjustments", handler.ListInvoiceAdjustments)

	billing.Post("/manual-adjustment", handler.CreateManualAdjustment)
	billing.Post("/manual-refund", handler.CreateManualRefund)
	billing.Post("/account-action", handler.PerformAccountAction)

	billing.Get("/accounts/:id/invoice-preview", handler.GetInvoicePreview)
	billing.Post("/coupons/:code/redeem", handler.RedeemCoupon)
	billing.Post("/invoices/:id/apply-credits", handler.ApplyCreditsToInvoice)
	billing.Get("/billing/config", handler.GetBillingConfig)
	billing.Post("/billing/config", handler.SetBillingConfig)
}
