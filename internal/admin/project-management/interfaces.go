package project_management

import (
	"context"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

type ProjectService interface {
	CreateProject(ctx context.Context, project Project) (Project, error)
	UpdateProject(ctx context.Context, project Project) (Project, error)
	DeleteProject(ctx context.Context, id string) error
	GetProject(ctx context.Context, id string) (Project, error)
	ListProjects(ctx context.Context, orgID string, page, pageSize int) ([]Project, error)
}

type ProjectMemberService interface {
	AddMember(ctx context.Context, member ProjectMember) (ProjectMember, error)
	RemoveMember(ctx context.Context, id string) error
	UpdateMember(ctx context.Context, member ProjectMember) (ProjectMember, error)
	GetMember(ctx context.Context, id string) (ProjectMember, error)
	ListMembers(ctx context.Context, projectID string, page, pageSize int) ([]ProjectMember, error)
}

type ProjectInviteService interface {
	CreateInvite(ctx context.Context, invite ProjectInvite) (ProjectInvite, error)
	AcceptInvite(ctx context.Context, token string) error
	RevokeInvite(ctx context.Context, id string) error
	ListInvites(ctx context.Context, projectID string, page, pageSize int) ([]ProjectInvite, error)
}

type ProjectSettingsService interface {
	GetSettings(ctx context.Context, projectID string) (ProjectSettings, error)
	UpdateSettings(ctx context.Context, projectID, settings string) error
}

type ProjectAuditLogger = security_management.AuditLogger

type ProjectAuditLogService interface {
	CreateAuditLog(ctx context.Context, log ProjectAuditLog) (ProjectAuditLog, error)
	ListAuditLogs(ctx context.Context, projectID, actorID, action string, page, pageSize int) ([]ProjectAuditLog, error)
}
