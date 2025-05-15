package billing_management

import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
)

type InvoiceService interface {
	CreateInvoice(input Invoice) (Invoice, error)
	UpdateInvoice(input Invoice) (Invoice, error)
	GetInvoice(id string) (Invoice, error)
	ListInvoices(accountID, status string, page, pageSize int) ([]Invoice, error)
	GetInvoicePreview(accountID string) (Invoice, error)
	GetBillingConfig() (map[string]interface{}, error)
	SetBillingConfig(input map[string]interface{}) error
	DeleteInvoice(id string) error
}

type PaymentService interface {
	CreatePayment(input payment.Payment) (payment.Payment, error)
	UpdatePayment(input payment.Payment) (payment.Payment, error)
	GetPayment(id string) (payment.Payment, error)
	ListPayments(invoiceID string, page, pageSize int) ([]payment.Payment, error)
	GetPaymentByIdempotencyKey(idempotencyKey string) (payment.Payment, error)

	RefundPayment(ctx context.Context, req *payment.RefundPaymentRequest) (*payment.PaymentResult, error)
	GetPaymentStatus(ctx context.Context, paymentID string) (*payment.PaymentStatus, error)
}

type RefundService interface {
	CreateRefund(input payment.Refund) (payment.Refund, error)
	UpdateRefund(id string) error
	DeleteRefund(id string) error
	GetRefund(id string) (payment.Refund, error)
	ListRefunds(paymentID, invoiceID, status string, page, pageSize int) ([]payment.Refund, error)
}

type PaymentMethodService interface {
	CreatePaymentMethod(input payment.PaymentMethod, data map[string]string) (payment.PaymentMethod, error)
	UpdatePaymentMethod(input payment.PaymentMethod) (payment.PaymentMethod, error)
	PatchPaymentMethod(id string, setDefault *bool, status string) error
	DeletePaymentMethod(id string) error
	GetPaymentMethod(id string) (payment.PaymentMethod, error)
	ListPaymentMethods(accountID, status string, page, pageSize int) ([]payment.PaymentMethod, error)
}

type WebhookEventService interface {
	CreateWebhookEvent(input WebhookEvent) (WebhookEvent, error)
	UpdateWebhookEvent(input WebhookEvent) (WebhookEvent, error)
	DeleteWebhookEvent(id string) error
	GetWebhookEvent(id string) (WebhookEvent, error)
	ListWebhookEvents(accountID, status string, page, pageSize int) ([]WebhookEvent, error)
}

type InvoiceAdjustmentService interface {
	CreateInvoiceAdjustment(input InvoiceAdjustment) (InvoiceAdjustment, error)
	UpdateInvoiceAdjustment(input InvoiceAdjustment) (InvoiceAdjustment, error)
	DeleteInvoiceAdjustment(id string) error
	GetInvoiceAdjustment(id string) (InvoiceAdjustment, error)
	ListInvoiceAdjustments(invoiceID string, page, pageSize int) ([]InvoiceAdjustment, error)
	ApplyCreditsToInvoice(accountID, invoiceID string) ([]InvoiceAdjustment, error)
}

// ManualAdjustmentService handles manual invoice adjustments
// All methods must be robust, user-friendly, and never leak sensitive info
type ManualAdjustmentService interface {
	CreateManualAdjustment(accountID, reason string, amount float64, currency string) error
}

// ManualRefundService handles manual refunds
// All methods must be robust, user-friendly, and never leak sensitive info

// AccountActionService handles account-level actions (e.g., suspend, activate, custom ops)
// All methods must be robust, user-friendly, and never leak sensitive info
type AccountActionService interface {
	PerformAccountAction(accountID, action string) error
}

type WebhookSubscriptionService interface {
	CreateWebhookSubscription(url, secret, description string, events []string) error
	DeleteWebhookSubscription(id string) error
	ListWebhookSubscriptions(tenantID string, page, pageSize int) ([]WebhookSubscription, error)
}

type TenantCurrencyService interface {
	SetTenantCurrency(ctx context.Context, tenantID, currency string) (TenantCurrency, error)
	GetTenantCurrency(ctx context.Context, tenantID string) (TenantCurrency, error)
}

// All audit logging must use AuditLogger for decoupling and optionality.
type BillingAuditLogger interface {
	LogBillingEvent(event string, actor string, target string, details string)
}

// DisputeServiceInterface defines admin dispute management contract
// (moved from types.go for consistency)
type DisputeServiceInterface interface {
	ListDisputes(ctx context.Context, tenantID, paymentID string, status payment.DisputeStatus, page, pageSize int) ([]*payment.Dispute, error)
	GetDispute(ctx context.Context, disputeID string) (*payment.Dispute, error)
	UpdateDisputeStatus(ctx context.Context, disputeID string, status payment.DisputeStatus, evidenceSubmitted *time.Time) error
}

type DisputeEvidenceServiceInterface interface {
	UploadEvidence(ctx context.Context, e *payment.DisputeEvidence) error
	ListEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*payment.DisputeEvidence, error)
	GetEvidence(ctx context.Context, evidenceID string) (*payment.DisputeEvidence, error)
	UpdateEvidenceStatus(ctx context.Context, evidenceID, providerStatus, providerResponse string) error
}
