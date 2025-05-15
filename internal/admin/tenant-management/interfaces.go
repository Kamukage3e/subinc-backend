package tenant_management

import (
	"context"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// TenantService handles core tenant operations
type TenantService interface {
	CreateTenant(ctx context.Context, tenant *Tenant) error
	GetTenant(ctx context.Context, id string) (Tenant, error)
	UpdateTenant(ctx context.Context, tenant *Tenant) error
	DeleteTenant(ctx context.Context, id string) error
	ListTenants(ctx context.Context) ([]interface{}, error)
	SearchTenants(ctx context.Context, filter TenantFilter) ([]interface{}, int, error)
	// TenantLifecycleService methods
	SetTenantStatus(ctx context.Context, tenantID string, status TenantStatus) error
	GetTenantStatus(ctx context.Context, tenantID string) (TenantStatus, error)
}

// All audit logging must use AuditLogger for decoupling and optionality.
type TenantAuditLogger = security_management.AuditLogger

// TenantSettingsService handles tenant settings operations
type TenantSettingsService interface {
	GetTenantSettings(ctx context.Context, tenantID string) (map[string]interface{}, error)
	UpdateTenantSettings(ctx context.Context, tenantID string, settings map[string]interface{}) (map[string]interface{}, error)
}

// TenantLifecycleService handles tenant lifecycle state operations
type TenantLifecycleService interface {
	SetTenantStatus(ctx context.Context, tenantID string, status TenantStatus) error
	GetTenantStatus(ctx context.Context, tenantID string) (TenantStatus, error)
}
