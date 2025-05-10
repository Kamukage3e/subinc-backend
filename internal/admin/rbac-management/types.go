package rbac_management

import (
	"time"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	db  *pgxpool.Pool
	logger      *logger.Logger
	AuditLogger security_management.AuditLogger
}

type RBACHandler struct {
	RoleService          RoleService
	PermissionService    PermissionService
	RoleBindingService   RoleBindingService
	PolicyService        PolicyService
	APIPermissionService APIPermissionService
	ResourceService      ResourceService
	AuditLogService      AuditLogService
	Store                *PostgresStore
	AuditLogger          security_management.AuditLogger
}

// --- Request structs for body-only input ---
type IDTenantRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}
type IDRequest struct {
	ID string `json:"id"`
}
type TenantRequest struct {
	TenantID string `json:"tenant_id"`
}
type ListRequest struct {
	TenantID string `json:"tenant_id"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type ListPermissionRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type ListRoleBindingRequest struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type ListAPIPermissionRequest struct {
	TenantID string `json:"tenant_id"`
	API      string `json:"api"`
	Method   string `json:"method"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type ListResourceRequest struct {
	TenantID string `json:"tenant_id"`
	Type     string `json:"type"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}
type ListAuditLogRequest struct {
	TenantID string `json:"tenant_id"`
	ActorID  string `json:"actor_id"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// Role defines a named set of permissions for a tenant or system
// ID is UUID, TenantID is required for tenant roles, Name is unique per tenant
// System roles have TenantID = ""
type Role struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Desc      string    `json:"desc"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Permission defines an action on a resource (API, object, etc.)
type Permission struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Desc      string    `json:"desc"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RoleBinding binds a role to a user or service account in a tenant
type RoleBinding struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	RoleID    string    `json:"role_id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserRole is a view of a user's roles in a tenant
type UserRole struct {
	UserID   string   `json:"user_id"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

// TenantRole is a view of all roles in a tenant
type TenantRole struct {
	TenantID string `json:"tenant_id"`
	Roles    []Role `json:"roles"`
}

// APIPermission is a fine-grained permission for an API endpoint
type APIPermission struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	API       string    `json:"api"`
	Method    string    `json:"method"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Resource is a managed object (API, project, etc.)
type Resource struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Policy defines a set of rules for access control
type Policy struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Statements []string  `json:"statements"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AuditLog for RBAC actions
type AuditLog struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	TargetID  string    `json:"target_id"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}
