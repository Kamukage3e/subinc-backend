package docmanagement

import (
	"context"

	billing_management "github.com/subinc/subinc-backend/internal/admin/billing-management"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
)

type DocumentStore interface {
	Get(ctx context.Context, id string) (*Document, error)
	List(ctx context.Context, filter DocumentFilter) ([]*Document, error)
	Create(ctx context.Context, input CreateDocumentInput) (*Document, error)
	Update(ctx context.Context, id string, input UpdateDocumentInput) (*Document, error)
	Delete(ctx context.Context, id string) error
}

type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) Row
}

type Result interface{}
type Rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
}
type Row interface {
	Scan(dest ...interface{}) error
}

// UnifiedSchemaDeps defines all dependencies required to build the unified schema.
type UnifiedSchemaDeps struct {
	DocumentResolver      DocumentResolver
	BillingResolver       BillingResolver
	UserResolver          UserResolver
	TenantResolver        TenantResolver
	OrganizationResolver  OrganizationResolver
	ProjectResolver       ProjectResolver
	RBACResolver          RBACResolver
	SecurityResolver      SecurityResolver
	ServerConfigResolver  ServerConfigResolver
	InvoiceResolver       InvoiceResolver
	PaymentResolver       PaymentResolver
	DiscountResolver      DiscountResolver
	CouponResolver        CouponResolver
	CreditResolver        CreditResolver
	RefundResolver        RefundResolver
	SubscriptionResolver  SubscriptionResolver
	PlanResolver          PlanResolver
	UsageResolver         UsageResolver
	PaymentMethodResolver PaymentMethodResolver
	WebhookResolver       WebhookResolver
	TaxResolver           TaxResolver
	AuditLogResolver      AuditLogResolver
	APIKeyResolver        APIKeyResolver
	RateLimitResolver     RateLimitResolver
	NotificationResolver  NotificationResolver
	AnalyticsResolver     AnalyticsResolver
	MFAResolver           MFAResolver
	OAuthResolver         OAuthResolver
	SAMLResolver          SAMLResolver
	DeviceResolver        DeviceResolver
	BreachResolver        BreachResolver
	PolicyResolver        PolicyResolver
}

// DocumentResolver defines the required document management resolver interface.
type DocumentResolver interface {
	Document(ctx context.Context, id string) (*Document, error)
	Documents(ctx context.Context, filter *DocumentFilter) ([]*Document, error)
	CreateDocument(ctx context.Context, input CreateDocumentInput) (*Document, error)
	UpdateDocument(ctx context.Context, id string, input UpdateDocumentInput) (*Document, error)
	DeleteDocument(ctx context.Context, id string) (bool, error)
}

type BillingResolver interface {
	GetAccount(ctx interface{}, id string) (*billing_management.Account, error)
	CreateAccount(ctx interface{}, input billing_management.Account) (*billing_management.Account, error)
}

type UserResolver interface {
	GetUser(ctx interface{}, id string) (*user_management.User, error)
	CreateUser(ctx interface{}, input user_management.User) (*user_management.User, error)
	GetUserProfile(ctx interface{}, userId string) (*user_management.UserProfile, error)
}

type TenantResolver interface {
	GetTenant(ctx interface{}, id string) (*tenant_management.Tenant, error)
	CreateTenant(ctx interface{}, input tenant_management.Tenant) (*tenant_management.Tenant, error)
	UpdateTenant(ctx interface{}, input tenant_management.Tenant) (*tenant_management.Tenant, error)
	DeleteTenant(ctx interface{}, id string) (bool, error)
}

// OrganizationResolver defines the required organization management resolver interface.
type OrganizationResolver interface {
	GetOrganization(ctx interface{}, id string) (interface{}, error)
	CreateOrganization(ctx interface{}, input interface{}) (interface{}, error)
	UpdateOrganization(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteOrganization(ctx interface{}, id string) (bool, error)
}

// ProjectResolver defines the required project management resolver interface.
type ProjectResolver interface {
	GetProject(ctx interface{}, id string) (interface{}, error)
	CreateProject(ctx interface{}, input interface{}) (interface{}, error)
	UpdateProject(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteProject(ctx interface{}, id string) (bool, error)
}

// RBACResolver defines the required RBAC management resolver interface.
type RBACResolver interface {
	GetRole(ctx interface{}, id string) (interface{}, error)
	CreateRole(ctx interface{}, input interface{}) (interface{}, error)
	UpdateRole(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteRole(ctx interface{}, id string) (bool, error)
	// Add more as needed for permissions, bindings, policies, etc.
}

// SecurityResolver defines the required security management resolver interface.
type SecurityResolver interface {
	GetSecurityEvent(ctx interface{}, id string) (interface{}, error)
	// Add more as needed for audit logs, MFA, etc.
}

// ServerConfigResolver defines the required server config management resolver interface.
type ServerConfigResolver interface {
	GetConfig(ctx interface{}, key string) (interface{}, error)
	SetConfig(ctx interface{}, key string, value interface{}) (interface{}, error)
}

// InvoiceResolver defines the required invoice management resolver interface.
type InvoiceResolver interface {
	GetInvoice(ctx interface{}, id string) (interface{}, error)
	CreateInvoice(ctx interface{}, input interface{}) (interface{}, error)
	UpdateInvoice(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteInvoice(ctx interface{}, id string) (bool, error)
}

// PaymentResolver defines the required payment management resolver interface.
type PaymentResolver interface {
	GetPayment(ctx interface{}, id string) (interface{}, error)
	CreatePayment(ctx interface{}, input interface{}) (interface{}, error)
	UpdatePayment(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeletePayment(ctx interface{}, id string) (bool, error)
}

// DiscountResolver defines the required discount management resolver interface.
type DiscountResolver interface {
	GetDiscount(ctx interface{}, id string) (interface{}, error)
	CreateDiscount(ctx interface{}, input interface{}) (interface{}, error)
	UpdateDiscount(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteDiscount(ctx interface{}, id string) (bool, error)
}

// CouponResolver defines the required coupon management resolver interface.
type CouponResolver interface {
	GetCoupon(ctx interface{}, id string) (interface{}, error)
	CreateCoupon(ctx interface{}, input interface{}) (interface{}, error)
	UpdateCoupon(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteCoupon(ctx interface{}, id string) (bool, error)
}

// CreditResolver defines the required credit management resolver interface.
type CreditResolver interface {
	GetCredit(ctx interface{}, id string) (interface{}, error)
	CreateCredit(ctx interface{}, input interface{}) (interface{}, error)
	UpdateCredit(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteCredit(ctx interface{}, id string) (bool, error)
}

// RefundResolver defines the required refund management resolver interface.
type RefundResolver interface {
	GetRefund(ctx interface{}, id string) (interface{}, error)
	CreateRefund(ctx interface{}, input interface{}) (interface{}, error)
	UpdateRefund(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteRefund(ctx interface{}, id string) (bool, error)
}

// SubscriptionResolver defines the required subscription management resolver interface.
type SubscriptionResolver interface {
	GetSubscription(ctx interface{}, id string) (interface{}, error)
	CreateSubscription(ctx interface{}, input interface{}) (interface{}, error)
	UpdateSubscription(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteSubscription(ctx interface{}, id string) (bool, error)
}

// PlanResolver defines the required plan management resolver interface.
type PlanResolver interface {
	GetPlan(ctx interface{}, id string) (interface{}, error)
	CreatePlan(ctx interface{}, input interface{}) (interface{}, error)
	UpdatePlan(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeletePlan(ctx interface{}, id string) (bool, error)
}

// UsageResolver defines the required usage management resolver interface.
type UsageResolver interface {
	GetUsage(ctx interface{}, id string) (interface{}, error)
	CreateUsage(ctx interface{}, input interface{}) (interface{}, error)
	UpdateUsage(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteUsage(ctx interface{}, id string) (bool, error)
}

// PaymentMethodResolver defines the required payment method management resolver interface.
type PaymentMethodResolver interface {
	GetPaymentMethod(ctx interface{}, id string) (interface{}, error)
	CreatePaymentMethod(ctx interface{}, input interface{}) (interface{}, error)
	UpdatePaymentMethod(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeletePaymentMethod(ctx interface{}, id string) (bool, error)
}

// WebhookResolver defines the required webhook management resolver interface.
type WebhookResolver interface {
	GetWebhook(ctx interface{}, id string) (interface{}, error)
	CreateWebhook(ctx interface{}, input interface{}) (interface{}, error)
	UpdateWebhook(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteWebhook(ctx interface{}, id string) (bool, error)
}

// TaxResolver defines the required tax management resolver interface.
type TaxResolver interface {
	GetTaxInfo(ctx interface{}, id string) (interface{}, error)
	CreateTaxInfo(ctx interface{}, input interface{}) (interface{}, error)
	UpdateTaxInfo(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteTaxInfo(ctx interface{}, id string) (bool, error)
}

// AuditLogResolver defines the required audit log management resolver interface.
type AuditLogResolver interface {
	GetAuditLog(ctx interface{}, id string) (interface{}, error)
	CreateAuditLog(ctx interface{}, input interface{}) (interface{}, error)
	UpdateAuditLog(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteAuditLog(ctx interface{}, id string) (bool, error)
}

// APIKeyResolver defines the required API key management resolver interface.
type APIKeyResolver interface {
	GetAPIKey(ctx interface{}, id string) (interface{}, error)
	CreateAPIKey(ctx interface{}, input interface{}) (interface{}, error)
	UpdateAPIKey(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteAPIKey(ctx interface{}, id string) (bool, error)
}

// RateLimitResolver defines the required rate limit management resolver interface.
type RateLimitResolver interface {
	GetRateLimit(ctx interface{}, id string) (interface{}, error)
	CreateRateLimit(ctx interface{}, input interface{}) (interface{}, error)
	UpdateRateLimit(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteRateLimit(ctx interface{}, id string) (bool, error)
}

// NotificationResolver defines the required notification management resolver interface.
type NotificationResolver interface {
	GetNotification(ctx interface{}, id string) (interface{}, error)
	CreateNotification(ctx interface{}, input interface{}) (interface{}, error)
	UpdateNotification(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteNotification(ctx interface{}, id string) (bool, error)
}

// AnalyticsResolver defines the required analytics management resolver interface.
type AnalyticsResolver interface {
	GetAnalytics(ctx interface{}, id string) (interface{}, error)
	CreateAnalytics(ctx interface{}, input interface{}) (interface{}, error)
	UpdateAnalytics(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteAnalytics(ctx interface{}, id string) (bool, error)
}

// MFAResolver defines the required MFA management resolver interface.
type MFAResolver interface {
	GetMFA(ctx interface{}, id string) (interface{}, error)
	CreateMFA(ctx interface{}, input interface{}) (interface{}, error)
	UpdateMFA(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteMFA(ctx interface{}, id string) (bool, error)
}

// OAuthResolver defines the required OAuth management resolver interface.
type OAuthResolver interface {
	GetOAuth(ctx interface{}, id string) (interface{}, error)
	CreateOAuth(ctx interface{}, input interface{}) (interface{}, error)
	UpdateOAuth(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteOAuth(ctx interface{}, id string) (bool, error)
}

// SAMLResolver defines the required SAML management resolver interface.
type SAMLResolver interface {
	GetSAML(ctx interface{}, id string) (interface{}, error)
	CreateSAML(ctx interface{}, input interface{}) (interface{}, error)
	UpdateSAML(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteSAML(ctx interface{}, id string) (bool, error)
}

// DeviceResolver defines the required device management resolver interface.
type DeviceResolver interface {
	GetDevice(ctx interface{}, id string) (interface{}, error)
	CreateDevice(ctx interface{}, input interface{}) (interface{}, error)
	UpdateDevice(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteDevice(ctx interface{}, id string) (bool, error)
}

// BreachResolver defines the required breach management resolver interface.
type BreachResolver interface {
	GetBreach(ctx interface{}, id string) (interface{}, error)
	CreateBreach(ctx interface{}, input interface{}) (interface{}, error)
	UpdateBreach(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeleteBreach(ctx interface{}, id string) (bool, error)
}

// PolicyResolver defines the required policy management resolver interface.
type PolicyResolver interface {
	GetPolicy(ctx interface{}, id string) (interface{}, error)
	CreatePolicy(ctx interface{}, input interface{}) (interface{}, error)
	UpdatePolicy(ctx interface{}, id string, input interface{}) (interface{}, error)
	DeletePolicy(ctx interface{}, id string) (bool, error)
}
