package billing_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminBillingRoutes(router fiber.Router, handler *BillingAdminHandler) {
	billing := router.Group("/billing-management")

	billing.Post("/accounts/create", handler.CreateAccount)
	billing.Put("/accounts/update", handler.UpdateAccount)
	billing.Get("/accounts/get", handler.GetAccount)
	billing.Get("/accounts/list", handler.ListAccounts)

	billing.Post("/plans/create", handler.CreatePlan)
	billing.Put("/plans/update", handler.UpdatePlan)
	billing.Get("/plans/get", handler.GetPlan)
	billing.Get("/plans/list", handler.ListPlans)
	billing.Delete("/plans/delete", handler.DeletePlan)

	billing.Post("/usage/create", handler.CreateUsage)
	billing.Get("/usage/list", handler.ListUsage)

	billing.Post("/invoices/create", handler.CreateInvoice)
	billing.Put("/invoices/update", handler.UpdateInvoice)
	billing.Get("/invoices/get", handler.GetInvoice)
	billing.Get("/invoices/list", handler.ListInvoices)

	billing.Post("/payments/create", handler.CreatePayment)
	billing.Put("/payments/update", handler.UpdatePayment)
	billing.Get("/payments/get", handler.GetPayment)
	billing.Get("/payments/list", handler.ListPayments)

	billing.Post("/discounts/create", handler.CreateDiscount)
	billing.Put("/discounts/update", handler.UpdateDiscount)
	billing.Delete("/discounts/delete", handler.DeleteDiscount)
	billing.Get("/discounts/get", handler.GetDiscount)
	billing.Get("/discounts/code/:code", handler.GetDiscountByCode)
	billing.Get("/discounts/list", handler.ListDiscounts)

	billing.Post("/coupons/create", handler.CreateCoupon)
	billing.Put("/coupons/update", handler.UpdateCoupon)
	billing.Delete("/coupons/delete", handler.DeleteCoupon)
	billing.Get("/coupons/get", handler.GetCoupon)
	billing.Get("/coupons/code/:code", handler.GetCouponByCode)
	billing.Get("/coupons/list", handler.ListCoupons)

	billing.Post("/credits/create", handler.CreateCredit)
	billing.Put("/credits/update", handler.UpdateCredit)
	billing.Patch("/credits/patch", handler.PatchCredit)
	billing.Delete("/credits/delete", handler.DeleteCredit)
	billing.Get("/credits/get", handler.GetCredit)
	billing.Get("/credits/list", handler.ListCredits)

	billing.Post("/refunds/create", handler.CreateRefund)
	billing.Put("/refunds/update", handler.UpdateRefund)
	billing.Delete("/refunds/delete", handler.DeleteRefund)
	billing.Get("/refunds/get", handler.GetRefund)
	billing.Get("/refunds/list", handler.ListRefunds)

	billing.Post("/payment-methods/create", handler.CreatePaymentMethod)
	billing.Put("/payment-methods/update", handler.UpdatePaymentMethod)
	billing.Patch("/payment-methods/patch", handler.PatchPaymentMethod)
	billing.Delete("/payment-methods/delete", handler.DeletePaymentMethod)
	billing.Get("/payment-methods/get", handler.GetPaymentMethod)
	billing.Get("/payment-methods/list", handler.ListPaymentMethods)

	billing.Post("/subscriptions/create", handler.CreateSubscription)
	billing.Put("/subscriptions/update", handler.UpdateSubscription)
	billing.Patch("/subscriptions/patch", handler.PatchSubscription)
	billing.Delete("/subscriptions/delete", handler.DeleteSubscription)
	billing.Get("/subscriptions/get", handler.GetSubscription)
	billing.Get("/subscriptions/list", handler.ListSubscriptions)
	billing.Post("/subscriptions/change-plan", handler.ChangePlanSubscription)
	billing.Post("/subscriptions/cancel", handler.CancelSubscriptionNow)
	billing.Post("/subscriptions/resume", handler.ResumeSubscription)
	billing.Post("/subscriptions/upgrade-now", handler.UpgradeNowSubscription)

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

	billing.Post("/manual-adjustment/create", handler.CreateManualAdjustment)
	billing.Post("/manual-refund/create", handler.CreateManualRefund)
	billing.Post("/account-action/perform", handler.PerformAccountAction)

	billing.Get("/accounts/invoice-preview", handler.GetInvoicePreview)
	billing.Post("/coupons/redeem/:code", handler.RedeemCoupon)

	billing.Get("/billing/config/get", handler.GetBillingConfig)
	billing.Post("/billing/config/set", handler.SetBillingConfig)

	billing.Post("/webhook-subscriptions/create", handler.CreateWebhookSubscription)
	billing.Get("/webhook-subscriptions/list", handler.ListWebhookSubscriptions)
	billing.Delete("/webhook-subscriptions/delete", handler.DeleteWebhookSubscription)

	billing.Post("/tax-info/set", handler.SetTaxInfo)
	billing.Get("/tax-info/get", handler.GetTaxInfo)

	billing.Get("/reports/revenue/get", handler.GetRevenueReport)
	billing.Get("/reports/accounts-receivable/get", handler.GetARReport)
	billing.Get("/reports/churn/get", handler.GetChurnReport)
	billing.Get("/usage/aggregate/get", handler.AggregateUsageForBillingCycle)
	billing.Get("/usage/overage/get", handler.CalculateOverageCharges)
	billing.Post("/invoices/with-fees-tax/create", handler.CreateInvoiceWithFeesAndTax)
}
