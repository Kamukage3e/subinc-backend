package organization_management

import (
	"context"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

type OrganizationService interface {
	CreateOrganization(ctx context.Context, org Organization) (Organization, error)
	UpdateOrganization(ctx context.Context, org Organization) (Organization, error)
	DeleteOrganization(ctx context.Context, id string) error
	GetOrganization(ctx context.Context, id string) (Organization, error)
	ListOrganizations(ctx context.Context, ownerID string, page, pageSize int) ([]Organization, error)
}

type OrgSettingsService interface {
	GetSettings(ctx context.Context, orgID string) (map[string]interface{}, error)
	UpdateSettings(ctx context.Context, orgID string, settings map[string]interface{}) error
}

// All audit logging must use OrgAuditLogger for decoupling and optionality. Never depend on a concrete implementation.
type OrgAuditLogger = security_management.AuditLogger
