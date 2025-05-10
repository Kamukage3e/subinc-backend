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

type OrgMemberService interface {
	AddMember(ctx context.Context, member OrgMember) (OrgMember, error)
	RemoveMember(ctx context.Context, id string) error
	UpdateMember(ctx context.Context, member OrgMember) (OrgMember, error)
	GetMember(ctx context.Context, id string) (OrgMember, error)
	ListMembers(ctx context.Context, orgID string, page, pageSize int) ([]OrgMember, error)
}

type OrgInviteService interface {
	CreateInvite(ctx context.Context, invite OrgInvite) (OrgInvite, error)
	AcceptInvite(ctx context.Context, token string) error
	RevokeInvite(ctx context.Context, id string) error
	ListInvites(ctx context.Context, orgID string, page, pageSize int) ([]OrgInvite, error)
}

type OrgDomainService interface {
	AddDomain(ctx context.Context, domain OrgDomain) (OrgDomain, error)
	VerifyDomain(ctx context.Context, id string) error
	RemoveDomain(ctx context.Context, id string) error
	ListDomains(ctx context.Context, orgID string) ([]OrgDomain, error)
}

type OrgSettingsService interface {
	GetSettings(ctx context.Context, orgID string) (OrgSettings, error)
	UpdateSettings(ctx context.Context, orgID, settings string) error
}

type OrgAuditLogger = security_management.AuditLogger

type OrgAuditLogService interface {
	CreateAuditLog(ctx context.Context, log OrgAuditLog) (OrgAuditLog, error)
	ListAuditLogs(ctx context.Context, orgID, actorID, action string, page, pageSize int) ([]OrgAuditLog, error)
}
