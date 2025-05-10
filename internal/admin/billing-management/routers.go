package billing_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminBillingRoutes(router fiber.Router, handler *BillingAdminHandler) {
	billing := router.Group("/billing-management")

	billing.Post("/accounts/create", handler.CreateAccount)
	billing.Put("/accounts/update/:id", handler.UpdateAccount)
	billing.Get("/accounts/get/:id", handler.GetAccount)
	billing.Get("/accounts/list", handler.ListAccounts)

	billing.Post("/plans/create", handler.CreatePlan)
	billing.Put("/plans/update/:id", handler.UpdatePlan)
	billing.Get("/plans/get/:id", handler.GetPlan)
	billing.Get("/plans/list", handler.ListPlans)
	billing.Delete("/plans/delete/:id", handler.DeletePlan)

	billing.Post("/usage/create", handler.CreateUsage)
	billing.Get("/usage/list", handler.ListUsage)

	billing.Post("/invoices/create", handler.CreateInvoice)
	billing.Put("/invoices/update/:id", handler.UpdateInvoice)
	billing.Get("/invoices/get/:id", handler.GetInvoice)
	billing.Get("/invoices/list", handler.ListInvoices)

	billing.Post("/payments/create", handler.CreatePayment)
	billing.Put("/payments/update/:id", handler.UpdatePayment)
	billing.Get("/payments/get/:id", handler.GetPayment)
	billing.Get("/payments/list", handler.ListPayments)
	
	billing.Post("/discounts/create", handler.CreateDiscount)
	billing.Put("/discounts/update/:id", handler.UpdateDiscount)
	billing.Delete("/discounts/delete/:id", handler.DeleteDiscount)
	billing.Get("/discounts/get/:id", handler.GetDiscount)
	billing.Get("/discounts/code/:code", handler.GetDiscountByCode)
	billing.Get("/discounts/list", handler.ListDiscounts)

	billing.Post("/coupons/create", handler.CreateCoupon)
	billing.Put("/coupons/update/:id", handler.UpdateCoupon)
	billing.Delete("/coupons/delete/:id", handler.DeleteCoupon)
	billing.Get("/coupons/get/:id", handler.GetCoupon)
	billing.Get("/coupons/code/:code", handler.GetCouponByCode)
	billing.Get("/coupons/list", handler.ListCoupons)

	billing.Post("/credits/create", handler.CreateCredit)
	billing.Put("/credits/update/:id", handler.UpdateCredit)
	billing.Patch("/credits/patch/:id", handler.PatchCredit)
	billing.Delete("/credits/delete/:id", handler.DeleteCredit)
	billing.Get("/credits/get/:id", handler.GetCredit)
	billing.Get("/credits/list", handler.ListCredits)

	billing.Post("/refunds/create", handler.CreateRefund)
	billing.Put("/refunds/update/:id", handler.UpdateRefund)
	billing.Delete("/refunds/delete/:id", handler.DeleteRefund)
	billing.Get("/refunds/get/:id", handler.GetRefund)
	billing.Get("/refunds/list", handler.ListRefunds)

	billing.Post("/payment-methods/create", handler.CreatePaymentMethod)
	billing.Put("/payment-methods/update/:id", handler.UpdatePaymentMethod)
	billing.Patch("/payment-methods/patch/:id", handler.PatchPaymentMethod)
	billing.Delete("/payment-methods/delete/:id", handler.DeletePaymentMethod)
	billing.Get("/payment-methods/get/:id", handler.GetPaymentMethod)
	billing.Get("/payment-methods/list", handler.ListPaymentMethods)

	billing.Post("/subscriptions/create", handler.CreateSubscription)
	billing.Put("/subscriptions/update/:id", handler.UpdateSubscription)
	billing.Patch("/subscriptions/patch/:id", handler.PatchSubscription)
	billing.Delete("/subscriptions/delete/:id", handler.DeleteSubscription)
	billing.Get("/subscriptions/get/:id", handler.GetSubscription)
	billing.Get("/subscriptions/list", handler.ListSubscriptions)
	billing.Post("/subscriptions/:id/change-plan", handler.ChangePlanSubscription)
	billing.Post("/subscriptions/:id/cancel", handler.CancelSubscriptionNow)
	billing.Post("/subscriptions/:id/resume", handler.ResumeSubscription)
	billing.Post("/subscriptions/:id/upgrade-now", handler.UpgradeNowSubscription)

	billing.Post("/webhook-events/create", handler.CreateWebhookEvent)
	billing.Put("/webhook-events/update/:id", handler.UpdateWebhookEvent)
	billing.Delete("/webhook-events/delete/:id", handler.DeleteWebhookEvent)
	billing.Get("/webhook-events/get/:id", handler.GetWebhookEvent)
	billing.Get("/webhook-events/list", handler.ListWebhookEvents)

	billing.Post("/invoice-adjustments/create", handler.CreateInvoiceAdjustment)
	billing.Put("/invoice-adjustments/update/:id", handler.UpdateInvoiceAdjustment)
	billing.Delete("/invoice-adjustments/delete/:id", handler.DeleteInvoiceAdjustment)
	billing.Get("/invoice-adjustments/get/:id", handler.GetInvoiceAdjustment)
	billing.Get("/invoice-adjustments/list", handler.ListInvoiceAdjustments)
	billing.Post("/invoices/apply-credits/:id", handler.ApplyCreditsToInvoice)

	billing.Post("/manual-adjustment/create", handler.CreateManualAdjustment)
	billing.Post("/manual-refund/create", handler.CreateManualRefund)
	billing.Post("/account-action/perform", handler.PerformAccountAction)

	billing.Get("/accounts/invoice-preview/:id", handler.GetInvoicePreview)
	billing.Post("/coupons/redeem/:code", handler.RedeemCoupon)

	billing.Get("/billing/config/get", handler.GetBillingConfig)
	billing.Post("/billing/config/set", handler.SetBillingConfig)

	billing.Post("/api-usage/create", handler.CreateAPIUsage)
	billing.Get("/api-usage/list", handler.ListAPIUsage)

	billing.Post("/api-keys/create", handler.CreateAPIKey)
	billing.Post("/api-keys/:id/rotate", handler.RotateAPIKey)
	billing.Post("/api-keys/:id/revoke", handler.RevokeAPIKey)
	billing.Get("/api-keys/list", handler.ListAPIKeys)

	billing.Post("/rate-limit/set", handler.SetRateLimit)
	billing.Get("/rate-limit/get", handler.GetRateLimit)

	billing.Post("/sla/set", handler.SetSLA)
	billing.Get("/sla/get", handler.GetSLA)

	billing.Post("/plugins/register", handler.RegisterPlugin)
	billing.Get("/plugins/list", handler.ListPlugins)
	billing.Put("/plugins/update/:id", handler.UpdatePlugin)
	billing.Delete("/plugins/delete/:id", handler.DeletePlugin)

	billing.Post("/webhook-subscriptions/create", handler.CreateWebhookSubscription)
	billing.Get("/webhook-subscriptions/list", handler.ListWebhookSubscriptions)
	billing.Delete("/webhook-subscriptions/delete/:id", handler.DeleteWebhookSubscription)

	billing.Post("/tax-info/set", handler.SetTaxInfo)
	billing.Get("/tax-info/get", handler.GetTaxInfo)

	billing.Get("/reports/revenue/get", handler.GetRevenueReport)
	billing.Get("/reports/accounts-receivable/get", handler.GetARReport)
	billing.Get("/reports/churn/get", handler.GetChurnReport)
	billing.Get("/usage/aggregate/get", handler.AggregateUsageForBillingCycle)
	billing.Get("/usage/overage/get", handler.CalculateOverageCharges)
	billing.Post("/invoices/with-fees-tax/create", handler.CreateInvoiceWithFeesAndTax)
}
