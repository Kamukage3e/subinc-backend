package repository

import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/cost/domain"
)

// CostRepository defines the interface for cost data storage
// Only production implementations are supported. No in-memory or dev/test repositories.
type CostRepository interface {
	// Cost data operations
	StoreCost(ctx context.Context, cost *domain.Cost) error
	StoreCosts(ctx context.Context, costs []*domain.Cost) error
	GetCostByID(ctx context.Context, id string) (*domain.Cost, error)
	QueryCosts(ctx context.Context, query domain.CostQuery) ([]*domain.Cost, int, error)

	// Summary operations
	GetCostSummary(ctx context.Context, query domain.CostQuery) (*domain.CostSummary, error)

	// Import operations
	CreateCostImport(ctx context.Context, costImport *domain.CostImport) error
	UpdateCostImport(ctx context.Context, costImport *domain.CostImport) error
	GetCostImportByID(ctx context.Context, id string) (*domain.CostImport, error)
	ListCostImports(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, page, pageSize int) ([]*domain.CostImport, int, error)

	// Budget operations
	CreateBudget(ctx context.Context, budget *domain.Budget) error
	UpdateBudget(ctx context.Context, budget *domain.Budget) error
	DeleteBudget(ctx context.Context, id string) error
	GetBudgetByID(ctx context.Context, id string) (*domain.Budget, error)
	ListBudgets(ctx context.Context, tenantID string, provider domain.CloudProvider, active bool, page, pageSize int) ([]*domain.Budget, int, error)

	// Anomaly operations
	CreateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error
	UpdateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error
	GetAnomalyByID(ctx context.Context, id string) (*domain.Anomaly, error)
	ListAnomalies(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, status string, page, pageSize int) ([]*domain.Anomaly, int, error)

	// Forecast operations
	StoreForecast(ctx context.Context, forecast *domain.Forecast) error
	GetForecast(ctx context.Context, tenantID string, provider domain.CloudProvider, accountID string, startTime, endTime time.Time) (*domain.Forecast, error)

	// HealthCheck performs a connectivity check on the repository
	HealthCheck(ctx context.Context) error
}

// BillingRepository defines the interface for billing data storage
// Only production implementations are supported. No in-memory or dev/test repositories.
type BillingRepository interface {
	// BillingAccount operations
	CreateBillingAccount(ctx context.Context, account *domain.BillingAccount) error
	UpdateBillingAccount(ctx context.Context, account *domain.BillingAccount) error
	GetBillingAccountByID(ctx context.Context, id string) (*domain.BillingAccount, error)
	ListBillingAccounts(ctx context.Context, tenantID string, page, pageSize int) ([]*domain.BillingAccount, int, error)

	// BillingPlan operations
	CreateBillingPlan(ctx context.Context, plan *domain.BillingPlan) error
	UpdateBillingPlan(ctx context.Context, plan *domain.BillingPlan) error
	GetBillingPlanByID(ctx context.Context, id string) (*domain.BillingPlan, error)
	ListBillingPlans(ctx context.Context, activeOnly bool, page, pageSize int) ([]*domain.BillingPlan, int, error)

	// UsageEvent operations
	CreateUsageEvent(ctx context.Context, event *domain.UsageEvent) error
	ListUsageEvents(ctx context.Context, accountID string, startTime, endTime time.Time, page, pageSize int) ([]*domain.UsageEvent, int, error)

	// Invoice operations
	CreateInvoice(ctx context.Context, invoice *domain.Invoice) error
	UpdateInvoice(ctx context.Context, invoice *domain.Invoice) error
	GetInvoiceByID(ctx context.Context, id string) (*domain.Invoice, error)
	ListInvoices(ctx context.Context, accountID string, status string, page, pageSize int) ([]*domain.Invoice, int, error)

	// Payment operations
	CreatePayment(ctx context.Context, payment *domain.Payment) error
	UpdatePayment(ctx context.Context, payment *domain.Payment) error
	GetPaymentByID(ctx context.Context, id string) (*domain.Payment, error)
	ListPayments(ctx context.Context, invoiceID string, page, pageSize int) ([]*domain.Payment, int, error)

	// AuditLog operations
	CreateAuditLog(ctx context.Context, log *domain.AuditLog) error
	ListAuditLogs(ctx context.Context, accountID string, action string, startTime, endTime time.Time, page, pageSize int) ([]*domain.AuditLog, int, error)

	// Credit operations
	CreateCredit(ctx context.Context, credit *domain.Credit) error
	UpdateCredit(ctx context.Context, credit *domain.Credit) error
	GetCreditByID(ctx context.Context, id string) (*domain.Credit, error)
	ListCredits(ctx context.Context, accountID, invoiceID, status string, page, pageSize int) ([]*domain.Credit, int, error)

	// Refund operations
	CreateRefund(ctx context.Context, refund *domain.Refund) error
	UpdateRefund(ctx context.Context, refund *domain.Refund) error
	GetRefundByID(ctx context.Context, id string) (*domain.Refund, error)
	ListRefunds(ctx context.Context, paymentID, invoiceID, status string, page, pageSize int) ([]*domain.Refund, int, error)

	// PaymentMethod operations
	CreatePaymentMethod(ctx context.Context, method *domain.PaymentMethod) error
	UpdatePaymentMethod(ctx context.Context, method *domain.PaymentMethod) error
	DeletePaymentMethod(ctx context.Context, id string) error
	GetPaymentMethodByID(ctx context.Context, id string) (*domain.PaymentMethod, error)
	ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.PaymentMethod, int, error)

	// Subscription operations
	CreateSubscription(ctx context.Context, sub *domain.Subscription) error
	UpdateSubscription(ctx context.Context, sub *domain.Subscription) error
	DeleteSubscription(ctx context.Context, id string) error
	GetSubscriptionByID(ctx context.Context, id string) (*domain.Subscription, error)
	ListSubscriptions(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.Subscription, int, error)

	// WebhookEvent operations
	CreateWebhookEvent(ctx context.Context, event *domain.WebhookEvent) error
	UpdateWebhookEvent(ctx context.Context, event *domain.WebhookEvent) error
	GetWebhookEventByID(ctx context.Context, id string) (*domain.WebhookEvent, error)
	ListWebhookEvents(ctx context.Context, provider, status, eventType string, page, pageSize int) ([]*domain.WebhookEvent, int, error)

	// InvoiceAdjustment operations
	CreateInvoiceAdjustment(ctx context.Context, adj *domain.InvoiceAdjustment) error
	UpdateInvoiceAdjustment(ctx context.Context, adj *domain.InvoiceAdjustment) error
	GetInvoiceAdjustmentByID(ctx context.Context, id string) (*domain.InvoiceAdjustment, error)
	ListInvoiceAdjustments(ctx context.Context, invoiceID, adjType string, page, pageSize int) ([]*domain.InvoiceAdjustment, int, error)

	// Discount operations
	ListDiscounts(ctx context.Context, isActive *bool, page, pageSize int) ([]*domain.Discount, int, error)
}

// DiscountRepository defines the interface for discount data storage
// Only production implementations are supported. No in-memory or dev/test repositories.
type DiscountRepository interface {
	// Discount operations
	CreateDiscount(ctx context.Context, discount *domain.Discount) error
	UpdateDiscount(ctx context.Context, discount *domain.Discount) error
	DeleteDiscount(ctx context.Context, id string) error
	GetDiscountByID(ctx context.Context, id string) (*domain.Discount, error)
	GetDiscountByCode(ctx context.Context, code string) (*domain.Discount, error)
	ListDiscounts(ctx context.Context, isActive *bool, page, pageSize int) ([]*domain.Discount, int, error)
}

// CouponRepository defines the interface for coupon data storage
// Only production implementations are supported. No in-memory or dev/test repositories.
type CouponRepository interface {
	CreateCoupon(ctx context.Context, coupon *domain.Coupon) error
	UpdateCoupon(ctx context.Context, coupon *domain.Coupon) error
	DeleteCoupon(ctx context.Context, id string) error
	GetCouponByID(ctx context.Context, id string) (*domain.Coupon, error)
	GetCouponByCode(ctx context.Context, code string) (*domain.Coupon, error)
	ListCoupons(ctx context.Context, discountID string, isActive *bool, page, pageSize int) ([]*domain.Coupon, int, error)
}
