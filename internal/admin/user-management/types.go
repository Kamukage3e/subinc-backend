package user_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
)

type PostgresStore struct {
	DB                  *pgxpool.Pool
	AuditLogger         security_management.AuditLogger
	ServerConfigService *server_config.Service
}
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserProfile struct {
	UserID    string    `json:"user_id"`
	FullName  string    `json:"full_name"`
	AvatarURL string    `json:"avatar_url"`
	Bio       string    `json:"bio"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserAuditLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

// Org membership
// Moved from organization_management
// All org/project membership/invite logic is now centralized here

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

// Project membership
// Moved from project_management

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

type UserHandler struct {
	Store            *PostgresStore
	RBACService      rbac_management.RBACService          // optional, may be nil
	RateLimitService security_management.RateLimitService // for distributed rate limiting
}
