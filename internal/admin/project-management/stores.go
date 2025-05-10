package project_management

import (
	"context"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// DB store implementations for project-management admin module will go here.



func (s *PostgresStore) logAudit(ctx context.Context, log ProjectAuditLog) {
	if s.AuditLogger == nil {
		s.AuditLogger = security_management.NoopAuditLogger{}
	}
	s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
		ID:        log.ID,
		ActorID:   log.ActorID,
		Action:    log.Action,
		TargetID:  log.TargetID,
		Details:   log.Details,
		CreatedAt: log.CreatedAt,
	})
}
