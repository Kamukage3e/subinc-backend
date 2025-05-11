package payment

import (
	"context"
	"time"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// PaymentProvider defines the interface for all payment providers (Stripe, PayPal, Braintree, etc).
// Implementations must support multiple payment methods (card, apple pay, google pay) via the Source field in CreatePaymentRequest.
type PaymentProvider interface {
	CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*PaymentResult, error)
	RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error)
	GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error)
}

// StoreInterface abstracts Store for testability and dynamic provider lookup
// Must be implemented by Store
type StoreInterface interface {
	GetTenantPaymentProviderConfig(ctx context.Context, tenantID string) (*TenantPaymentProviderConfig, error)
	GetTenantProviderSecret(ctx context.Context, tenantID, provider string) (map[string]string, error)
	SavePayment(ctx context.Context, p *PaymentResult) error
	GetPayment(ctx context.Context, paymentID string) (*PaymentResult, error)
	// Dunning methods
	ListFailedPayments(ctx context.Context, tenantID string) ([]*FailedPayment, error)
	GetDunningConfig(ctx context.Context, tenantID string) (*DunningConfig, error)
	UpdateDunningState(ctx context.Context, paymentID, state string, attempts int) error
	UpdateDunningAttempt(ctx context.Context, paymentID string, lastAttempt time.Time, attempts int) error
}

// DisputeEvidenceStoreInterface abstracts evidence storage for testability and multi-tenant support
// All methods must be robust, multi-tenant, and audit-friendly
type DisputeEvidenceStoreInterface interface {
	CreateDisputeEvidence(ctx context.Context, e *DisputeEvidence) error
	GetDisputeEvidence(ctx context.Context, evidenceID string) (*DisputeEvidence, error)
	ListDisputeEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*DisputeEvidence, error)
	UpdateDisputeEvidenceStatus(ctx context.Context, evidenceID, providerStatus, providerResponse string) error
}

// DisputeEvidenceService handles evidence upload, provider sync, audit, and admin endpoints
// All methods robust, multi-tenant, audit-logged

type DisputeEvidenceService struct {
	Store       DisputeEvidenceStoreInterface
	Notify      security_management.NotificationService
	AuditLogger security_management.AuditLogger
}