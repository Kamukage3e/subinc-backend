package organization_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
	project_management "github.com/subinc/subinc-backend/internal/admin/project-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	OwnerID   string    `json:"owner_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type OrgMember struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	InvitedBy string    `json:"invited_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type OrgInvite struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type OrgDomain struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Domain    string    `json:"domain"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

type OrgSettings struct {
	OrgID     string    `json:"org_id"`
	Settings  string    `json:"settings"`
	UpdatedAt time.Time `json:"updated_at"`
}

type OrgAuditLog struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type PostgresStore struct {
	db          *pgxpool.Pool
	logger      *logger.Logger
	AuditLogger security_management.AuditLogger
}

type OrganizationHandler struct {
	OrganizationService OrganizationService
	OrgInviteService    OrgInviteService
	OrgSettingsService  OrgSettingsService
	OrgAuditLogger      OrgAuditLogger
	UserService         user_management.UserService    // optional, may be nil
	RBACService         rbac_management.RBACService    // optional, may be nil
	ProjectService      project_management.ProjectService // optional, may be nil
	Store               *PostgresStore
}