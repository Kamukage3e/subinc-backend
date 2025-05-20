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

type ProjectSettingsService interface {
	GetSettings(ctx context.Context, projectID string) (map[string]interface{}, error)
	UpdateSettings(ctx context.Context, projectID string, settings map[string]interface{}) (map[string]interface{}, error)
}

type ProjectAuditLogger = security_management.AuditLogger

type ProjectAuditLogService interface {
	CreateAuditLog(ctx context.Context, log ProjectAuditLog) (ProjectAuditLog, error)
	ListAuditLogs(ctx context.Context, projectID, actorID, action string, page, pageSize int) ([]ProjectAuditLog, error)
}
