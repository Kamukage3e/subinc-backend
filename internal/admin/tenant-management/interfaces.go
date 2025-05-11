package tenant_management

import (
	"context"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

type TenantService interface {
	CreateTenant(tenant *Tenant) error
	UpdateTenant(tenant *Tenant) error
	DeleteTenant(id string) error
	ListTenants() ([]interface{}, error)
	SearchTenants(filter TenantFilter) ([]interface{}, int, error)
}

// All audit logging must use AuditLogger for decoupling and optionality.
type TenantAuditLogger = security_management.AuditLogger

type TenantLifecycleService interface {
	SetTenantStatus(ctx context.Context, tenantID string, status TenantStatus) error
	GetTenantStatus(ctx context.Context, tenantID string) (TenantStatus, error)
}
