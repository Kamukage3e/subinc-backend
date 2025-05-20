package project_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
)

type ProjectHandler struct {
	ProjectService         ProjectService
	ProjectSettingsService ProjectSettingsService
	ProjectAuditLogService ProjectAuditLogService

	RateLimitService       security_management.RateLimitService // for distributed rate limiting
	UserService            user_management.UserService          // optional, may be nil
	Store                  *PostgresStore
}

type Project struct {
	ID          string            `json:"id"`
	OrgID       string            `json:"org_id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Status      string            `json:"status"`
	Tags        map[string]string `json:"tags"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
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
	DB                  *pgxpool.Pool

	ServerConfigService *server_config.Service
}
