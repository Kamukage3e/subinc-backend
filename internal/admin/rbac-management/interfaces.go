package rbac_management

import (
	"context"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// RoleService manages roles for tenants and system
// All methods are context-aware and multi-tenant
// All errors must be robust and user-friendly
// All returned slices are never nil
// All IDs are UUIDs
// All timestamps are UTC
// All methods are production-grade
// No placeholders
type RoleService interface {
	CreateRole(ctx context.Context, role Role) (Role, error)
	UpdateRole(ctx context.Context, role Role) (Role, error)
	DeleteRole(ctx context.Context, id, tenantID string) error
	GetRole(ctx context.Context, id, tenantID string) (Role, error)
	ListRoles(ctx context.Context, tenantID string, page, pageSize int) ([]Role, error)
}

type PermissionService interface {
	CreatePermission(ctx context.Context, perm Permission) (Permission, error)
	UpdatePermission(ctx context.Context, perm Permission) (Permission, error)
	DeletePermission(ctx context.Context, id string) error
	GetPermission(ctx context.Context, id string) (Permission, error)
	ListPermissions(ctx context.Context, resource, action string, page, pageSize int) ([]Permission, error)
}

type RoleBindingService interface {
	CreateRoleBinding(ctx context.Context, binding RoleBinding) (RoleBinding, error)
	DeleteRoleBinding(ctx context.Context, id string) error
	ListRoleBindings(ctx context.Context, tenantID, userID string, page, pageSize int) ([]RoleBinding, error)
}

type PolicyService interface {
	CreatePolicy(ctx context.Context, policy Policy) (Policy, error)
	UpdatePolicy(ctx context.Context, policy Policy) (Policy, error)
	DeletePolicy(ctx context.Context, id string) error
	GetPolicy(ctx context.Context, id string) (Policy, error)
	ListPolicies(ctx context.Context, tenantID string, page, pageSize int) ([]Policy, error)
}

type APIPermissionService interface {
	CreateAPIPermission(ctx context.Context, perm APIPermission) (APIPermission, error)
	DeleteAPIPermission(ctx context.Context, id string) error
	ListAPIPermissions(ctx context.Context, tenantID, api, method string, page, pageSize int) ([]APIPermission, error)
}

type ResourceService interface {
	CreateResource(ctx context.Context, res Resource) (Resource, error)
	UpdateResource(ctx context.Context, res Resource) (Resource, error)
	DeleteResource(ctx context.Context, id string) error
	GetResource(ctx context.Context, id string) (Resource, error)
	ListResources(ctx context.Context, tenantID, typ string, page, pageSize int) ([]Resource, error)
}

type AuditLogService interface {
	CreateAuditLog(ctx context.Context, log AuditLog) (AuditLog, error)
	ListAuditLogs(ctx context.Context, tenantID, actorID, action, resource string, page, pageSize int) ([]AuditLog, error)
}

// All audit logging must use AuditLogger for decoupling and optionality.
type RBACAuditLogger = security_management.AuditLogger

// RBACService provides full RBAC enforcement for all modules.
// All methods must be robust, user-friendly, and never leak sensitive info.
// This interface is required for SaaS-grade RBAC integration.
type RBACService interface {
	CheckPermission(ctx context.Context, userID, resource, action string) (bool, error)
	GetUserRoles(ctx context.Context, userID, resource string) ([]string, error)
}
