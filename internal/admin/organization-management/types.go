package organization_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	project_management "github.com/subinc/subinc-backend/internal/admin/project-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
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

type PostgresStore struct {
	DB                  *pgxpool.Pool
	AuditLogger         security_management.AuditLogger
	ServerConfigService *server_config.Service
}

type OrganizationHandler struct {
	OrganizationService OrganizationService
	OrgSettingsService  OrgSettingsService
	OrgAuditLogger      OrgAuditLogger
	UserService         user_management.UserService          // optional, may be nil
	RateLimitService    security_management.RateLimitService // for distributed rate limiting
	ProjectService      project_management.ProjectService    // optional, may be nil
	Store               *PostgresStore
}
