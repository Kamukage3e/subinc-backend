package tenant_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Tenant represents a SaaS tenant/org
// All fields are required for production
// Settings is a JSON blob for org settings/policies
// CreatedAt/UpdatedAt are UTC
// ID is UUID
// Name is unique per tenant
type Tenant struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Settings  string    `json:"settings" db:"settings"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// TenantSettings is a map for settings JSON
// Used for settings endpoints
type TenantSettings map[string]interface{}

// TenantFilter for search, sort, pagination
// Used by list/search endpoints
type TenantFilter struct {
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

type TenantAdminHandler struct {
	// TenantStore is optional for deployments that do not require tenant management.
	TenantStore *TenantStore // optional
	// TenantSettingsStore is optional for deployments that do not require tenant settings management.
	TenantSettingsStore *TenantSettingsStore // optional
	// AuditLogger is optional for deployments that do not require audit logging.
	AuditLogger security_management.AuditLogger // optional
	// RBACService is optional and only required if tenant management needs to delegate to RBAC.
	RBACService rbac_management.RBACService // optional, may be nil
	// UserHandler is optional and only required if tenant management needs to delegate to user management.
	UserHandler *user_management.UserHandler // optional
}

type TenantSettingsStore struct {
	DB  *pgxpool.Pool
	log *logger.Logger
}
