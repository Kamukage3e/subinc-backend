package project_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
)

type ProjectAdminHandler struct {
	ProjectService         ProjectService
	ProjectMemberService   ProjectMemberService
	ProjectInviteService   ProjectInviteService
	ProjectSettingsService ProjectSettingsService
	ProjectAuditLogService ProjectAuditLogService
	SecurityAuditLogger    security_management.AuditLogger // optional, may be nil
	RBACService            rbac_management.RBACService     // optional, may be nil
	UserService            user_management.UserService     // optional, may be nil
	Store                  *PostgresStore
}

type Project struct {
	ID          string            `json:"id"`
	OrgID       string            `json:"org_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Status      string            `json:"status"`
	Tags        map[string]string `json:"tags"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type ProjectMember struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	InvitedBy string    `json:"invited_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ProjectInvite struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type ProjectSettings struct {
	ProjectID string    `json:"project_id"`
	Settings  string    `json:"settings"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ProjectAuditLog struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

type DBError struct {
	Op  string
	Err error
}

type PostgresStore struct {
	db          *pgxpool.Pool
	AuditLogger security_management.AuditLogger
}
