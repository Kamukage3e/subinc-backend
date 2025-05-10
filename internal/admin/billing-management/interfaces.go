package billing_management

type AccountService interface {
	CreateAccount(input Account) (Account, error)
	UpdateAccount(input Account) (Account, error)
	GetAccount(id string) (Account, error)
	ListAccounts(tenantID string, page, pageSize int) ([]Account, error)
}

type PlanService interface {
	CreatePlan(input Plan) (Plan, error)
	UpdatePlan(input Plan) (Plan, error)
	GetPlan(id string) (Plan, error)
	ListPlans(activeOnly bool, page, pageSize int) ([]Plan, error)
	DeletePlan(id string) error
}

type UsageService interface {
	CreateUsage(input Usage) (Usage, error)
	ListUsage(accountID, metric, period string, page, pageSize int) ([]Usage, error)
}

type InvoiceService interface {
	CreateInvoice(input Invoice) (Invoice, error)
	UpdateInvoice(input Invoice) (Invoice, error)
	GetInvoice(id string) (Invoice, error)
	ListInvoices(accountID, status string, page, pageSize int) ([]Invoice, error)
	GetInvoicePreview(accountID string) (Invoice, error)
	GetBillingConfig() (map[string]interface{}, error)
	SetBillingConfig(input map[string]interface{}) error
}

type PaymentService interface {
	CreatePayment(input Payment) (Payment, error)
	UpdatePayment(input Payment) (Payment, error)
	GetPayment(id string) (Payment, error)
	ListPayments(invoiceID string, page, pageSize int) ([]Payment, error)
}

type AuditLogService interface {
	CreateAuditLog(input AuditLog) (AuditLog, error)
	ListAuditLogs(accountID, action string, page, pageSize int) ([]AuditLog, error)
	SearchAuditLogs(accountID, action, startTime, endTime string, page, pageSize int) ([]AuditLog, error)
}

type DiscountService interface {
	CreateDiscount(input Discount) (Discount, error)
	UpdateDiscount(input Discount) (Discount, error)
	DeleteDiscount(id string) error
	GetDiscount(id string) (Discount, error)
	GetDiscountByCode(code string) (Discount, error)
	ListDiscounts(activeOnly bool, page, pageSize int) ([]Discount, error)
}

type CouponService interface {
	CreateCoupon(input Coupon) (Coupon, error)
	UpdateCoupon(input Coupon) (Coupon, error)
	DeleteCoupon(id string) error
	GetCoupon(id string) (Coupon, error)
	GetCouponByCode(code string) (Coupon, error)
	ListCoupons(discountID string, isActive *bool, page, pageSize int) ([]Coupon, error)
	RedeemCoupon(code, accountID string) (Coupon, error)
}

type CreditService interface {
	CreateCredit(input Credit) (Credit, error)
	UpdateCredit(input Credit) (Credit, error)
	PatchCredit(id, action string, amount float64) error
	DeleteCredit(id string) error
	GetCredit(id string) (Credit, error)
	ListCredits(accountID, invoiceID, status string, page, pageSize int) ([]Credit, error)
	ApplyCreditsToInvoice(invoiceID string) error
}

type RefundService interface {
	CreateRefund(input Refund) (Refund, error)
	UpdateRefund(id string) error
	DeleteRefund(id string) error
	GetRefund(id string) (Refund, error)
	ListRefunds(paymentID, invoiceID, status string, page, pageSize int) ([]Refund, error)
}

type PaymentMethodService interface {
	CreatePaymentMethod(input PaymentMethod, data map[string]string) (PaymentMethod, error)
	UpdatePaymentMethod(input PaymentMethod) (PaymentMethod, error)
	PatchPaymentMethod(id string, setDefault *bool, status string) error
	DeletePaymentMethod(id string) error
	GetPaymentMethod(id string) (PaymentMethod, error)
	ListPaymentMethods(accountID, status string, page, pageSize int) ([]PaymentMethod, error)
}

type SubscriptionService interface {
	CreateSubscription(input Subscription) (Subscription, error)
	UpdateSubscription(input Subscription) (Subscription, error)
	PatchSubscription(id, action string) error
	DeleteSubscription(id string) error
	GetSubscription(id string) (Subscription, error)
	ListSubscriptions(accountID, status string, page, pageSize int) ([]Subscription, error)
	ChangePlanSubscription(id, planID string) error
	CancelSubscriptionNow(id string) error
	ResumeSubscription(id string) error
	UpgradeNowSubscription(id string) error
}

type WebhookEventService interface {
	CreateWebhookEvent(input WebhookEvent) (WebhookEvent, error)
	UpdateWebhookEvent(id string) error
	DeleteWebhookEvent(id string) error
	GetWebhookEvent(id string) (WebhookEvent, error)
	ListWebhookEvents(provider, status, eventType string, page, pageSize int) ([]WebhookEvent, error)
}

type InvoiceAdjustmentService interface {
	CreateInvoiceAdjustment(input InvoiceAdjustment) (InvoiceAdjustment, error)
	UpdateInvoiceAdjustment(id string) error
	DeleteInvoiceAdjustment(id string) error
	GetInvoiceAdjustment(id string) (InvoiceAdjustment, error)
	ListInvoiceAdjustments(invoiceID, adjType string, page, pageSize int) ([]InvoiceAdjustment, error)
}

// ManualAdjustmentService handles manual invoice adjustments
// All methods must be robust, user-friendly, and never leak sensitive info
type ManualAdjustmentService interface {
	CreateManualAdjustment(input InvoiceAdjustment) (InvoiceAdjustment, error)
}

// ManualRefundService handles manual refunds
// All methods must be robust, user-friendly, and never leak sensitive info
type ManualRefundService interface {
	CreateManualRefund(input Refund) (Refund, error)
}

// AccountActionService handles account-level actions (e.g., suspend, activate, custom ops)
// All methods must be robust, user-friendly, and never leak sensitive info
type AccountActionService interface {
	PerformAccountAction(accountID, action string, params map[string]interface{}) (map[string]interface{}, error)
}

var _ AccountActionService = (*PostgresStore)(nil)
