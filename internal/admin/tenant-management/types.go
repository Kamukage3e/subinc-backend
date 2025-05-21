package tenant_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
)

// TenantStatus defines valid lifecycle states for a tenant
// Valid values: pending, active, suspended, deleted
type TenantStatus string

const (
	// TenantStatusPending indicates a tenant that is provisioning or awaiting approval
	TenantStatusPending TenantStatus = "pending"
	// TenantStatusActive indicates a tenant that is fully operational
	TenantStatusActive TenantStatus = "active"
	// TenantStatusSuspended indicates a tenant that is temporarily disabled
	TenantStatusSuspended TenantStatus = "suspended"
	// TenantStatusDeleted indicates a tenant that is marked for deletion
	TenantStatusDeleted TenantStatus = "deleted"
)

// Tenant represents a SaaS tenant/organization
// All fields are required for production environments
// Settings is stored as a JSON blob for tenant-specific settings and policies
// CreatedAt/UpdatedAt timestamps are in UTC
// ID is a UUID string
// Name is unique per tenant
type Tenant struct {
	ID        string       `json:"id" db:"id"`
	Name      string       `json:"name" db:"name"`
	Status    TenantStatus `json:"status" db:"status"`
	Settings  string       `json:"settings" db:"settings"`
	CreatedAt time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt time.Time    `json:"updated_at" db:"updated_at"`
}

// TenantSettings is a map for tenant settings
// Used for settings endpoints to handle dynamic configuration values
type TenantSettings map[string]interface{}

// TenantFilter defines parameters for searching, sorting, and paginating tenants
// Used by list/search endpoints
type TenantFilter struct {
	// Query is the search term for filtering tenants by name
	Query string
	// SortBy specifies the field to sort results by
	SortBy string
	// SortDir specifies sort direction (asc/desc)
	SortDir string
	// Limit controls how many results to return
	Limit int
	// Offset controls pagination starting point
	Offset int
}

// TenantAdminHandler handles HTTP requests for tenant administration
// Implements all RESTful tenant management endpoints
type TenantAdminHandler struct {
	// TenantStore provides core tenant operations
	// Required for all tenant management functionality
	TenantStore TenantService

	// TenantSettingsStore handles tenant settings management
	// Can be the same instance as TenantStore
	TenantSettingsStore TenantSettingsService

	// AuditLogger records security-relevant tenant operations
	// Optional for deployments that don't require audit logging

	// UserHandler handles delegated user operations
	// Optional for deployments that don't need user management integration
	UserHandler *user_management.UserHandler
}

// PostgresStore implements persistence layer for tenant operations
// Provides implementation for TenantService, TenantSettingsService,
// and TenantLifecycleService interfaces
type PostgresStore struct {
	// DB is the PostgreSQL connection pool
	DB *pgxpool.Pool

	// AuditLogger records security-relevant database operations

	// ServerConfigService provides access to server configuration
	ServerConfigService *server_config.Service
}
