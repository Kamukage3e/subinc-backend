package rbac_management

import (
	"context"

	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Remove the PostgresStore struct definition from this file. Only use the one from types.go.

func NewPostgresStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

// --- RoleService ---
func (s *PostgresStore) CreateRole(ctx context.Context, role Role) (Role, error) {
	const q = `INSERT INTO roles (id, tenant_id, name, desc, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, tenant_id, name, desc, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRow(ctx, q, id, role.TenantID, role.Name, role.Desc, now, now)
	var out Role
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.Desc, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateRole failed", logger.ErrorField(err), logger.Any("role", role))
		return Role{}, err
	}

	return out, nil
}

func (s *PostgresStore) UpdateRole(ctx context.Context, role Role) (Role, error) {
	const q = `UPDATE roles SET name = $2, desc = $3, updated_at = $4 WHERE id = $1 AND tenant_id = $5 RETURNING id, tenant_id, name, desc, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, role.ID, role.Name, role.Desc, time.Now().UTC(), role.TenantID)
	var out Role
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.Desc, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdateRole failed", logger.ErrorField(err), logger.Any("role", role))
		return Role{}, err
	}
	// Add audit log after update

	return out, nil
}

func (s *PostgresStore) DeleteRole(ctx context.Context, id, tenantID string) error {
	const q = `DELETE FROM roles WHERE id = $1 AND tenant_id = $2`
	_, err := s.db.Exec(ctx, q, id, tenantID)
	if err != nil {
		s.logger.Error("DeleteRole failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	return nil
}

func (s *PostgresStore) GetRole(ctx context.Context, id, tenantID string) (Role, error) {
	const q = `SELECT id, tenant_id, name, desc, created_at, updated_at FROM roles WHERE id = $1 AND tenant_id = $2`
	row := s.db.QueryRow(ctx, q, id, tenantID)
	var out Role
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.Desc, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetRole failed", logger.ErrorField(err), logger.String("id", id))
		return Role{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListRoles(ctx context.Context, tenantID string, page, pageSize int) ([]Role, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, tenant_id, name, desc, created_at, updated_at FROM roles WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, q, tenantID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListRoles query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Desc, &r.CreatedAt, &r.UpdatedAt); err != nil {
			s.logger.Error("ListRoles scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// --- PermissionService ---
func (s *PostgresStore) CreatePermission(ctx context.Context, perm Permission) (Permission, error) {
	const q = `INSERT INTO permissions (id, name, resource, action, desc, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, resource, action, desc, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRow(ctx, q, id, perm.Name, perm.Resource, perm.Action, perm.Desc, now, now)
	var out Permission
	if err := row.Scan(&out.ID, &out.Name, &out.Resource, &out.Action, &out.Desc, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreatePermission failed", logger.ErrorField(err), logger.Any("perm", perm))
		return Permission{}, err
	}

	return out, nil
}

func (s *PostgresStore) UpdatePermission(ctx context.Context, perm Permission) (Permission, error) {
	const q = `UPDATE permissions SET name = $2, resource = $3, action = $4, desc = $5, updated_at = $6 WHERE id = $1 RETURNING id, name, resource, action, desc, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, perm.ID, perm.Name, perm.Resource, perm.Action, perm.Desc, time.Now().UTC())
	var out Permission
	if err := row.Scan(&out.ID, &out.Name, &out.Resource, &out.Action, &out.Desc, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdatePermission failed", logger.ErrorField(err), logger.Any("perm", perm))
		return Permission{}, err
	}

	return out, nil
}

func (s *PostgresStore) DeletePermission(ctx context.Context, id string) error {
	const q = `DELETE FROM permissions WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	if err != nil {
		s.logger.Error("DeletePermission failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	return nil
}

func (s *PostgresStore) GetPermission(ctx context.Context, id string) (Permission, error) {
	const q = `SELECT id, name, resource, action, desc, created_at, updated_at FROM permissions WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Permission
	if err := row.Scan(&out.ID, &out.Name, &out.Resource, &out.Action, &out.Desc, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetPermission failed", logger.ErrorField(err), logger.String("id", id))
		return Permission{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListPermissions(ctx context.Context, resource, action string, page, pageSize int) ([]Permission, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, name, resource, action, desc, created_at, updated_at FROM permissions WHERE 1=1`
	args := []interface{}{}
	if resource != "" {
		q += " AND resource = $1"
		args = append(args, resource)
	}
	if action != "" {
		q += " AND action = $2"
		args = append(args, action)
	}
	q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListPermissions query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Resource, &p.Action, &p.Desc, &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("ListPermissions scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// --- RoleBindingService ---
func (s *PostgresStore) CreateRoleBinding(ctx context.Context, binding RoleBinding) (RoleBinding, error) {
	const q = `INSERT INTO role_bindings (id, tenant_id, role_id, user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, tenant_id, role_id, user_id, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRow(ctx, q, id, binding.TenantID, binding.RoleID, binding.UserID, now, now)
	var out RoleBinding
	if err := row.Scan(&out.ID, &out.TenantID, &out.RoleID, &out.UserID, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateRoleBinding failed", logger.ErrorField(err), logger.Any("binding", binding))
		return RoleBinding{}, err
	}

	return out, nil
}

func (s *PostgresStore) DeleteRoleBinding(ctx context.Context, id string) error {
	const q = `DELETE FROM role_bindings WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	if err != nil {
		s.logger.Error("DeleteRoleBinding failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	return nil
}

func (s *PostgresStore) ListRoleBindings(ctx context.Context, tenantID, userID string, page, pageSize int) ([]RoleBinding, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, tenant_id, role_id, user_id, created_at, updated_at FROM role_bindings WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if userID != "" {
		q += " AND user_id = $2"
		args = append(args, userID)
	}
	q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListRoleBindings query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []RoleBinding
	for rows.Next() {
		var b RoleBinding
		if err := rows.Scan(&b.ID, &b.TenantID, &b.RoleID, &b.UserID, &b.CreatedAt, &b.UpdatedAt); err != nil {
			s.logger.Error("ListRoleBindings scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// --- PolicyService ---
func (s *PostgresStore) CreatePolicy(ctx context.Context, policy Policy) (Policy, error) {
	const q = `INSERT INTO policies (id, tenant_id, name, statements, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, tenant_id, name, statements, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRow(ctx, q, id, policy.TenantID, policy.Name, pq.Array(policy.Statements), now, now)
	var out Policy
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, pq.Array(&out.Statements), &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreatePolicy failed", logger.ErrorField(err), logger.Any("policy", policy))
		return Policy{}, err
	}

	return out, nil
}

func (s *PostgresStore) UpdatePolicy(ctx context.Context, policy Policy) (Policy, error) {
	const q = `UPDATE policies SET name = $2, statements = $3, updated_at = $4 WHERE id = $1 RETURNING id, tenant_id, name, statements, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, policy.ID, policy.Name, pq.Array(policy.Statements), time.Now().UTC())
	var out Policy
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, pq.Array(&out.Statements), &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdatePolicy failed", logger.ErrorField(err), logger.Any("policy", policy))
		return Policy{}, err
	}

	return out, nil
}

func (s *PostgresStore) DeletePolicy(ctx context.Context, id string) error {
	const q = `DELETE FROM policies WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	if err != nil {
		s.logger.Error("DeletePolicy failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	return nil
}

func (s *PostgresStore) GetPolicy(ctx context.Context, id string) (Policy, error) {
	const q = `SELECT id, tenant_id, name, statements, created_at, updated_at FROM policies WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Policy
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, pq.Array(&out.Statements), &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetPolicy failed", logger.ErrorField(err), logger.String("id", id))
		return Policy{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListPolicies(ctx context.Context, tenantID string, page, pageSize int) ([]Policy, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, tenant_id, name, statements, created_at, updated_at FROM policies WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, q, tenantID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListPolicies query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, pq.Array(&p.Statements), &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("ListPolicies scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// --- APIPermissionService ---
func (s *PostgresStore) CreateAPIPermission(ctx context.Context, perm APIPermission) (APIPermission, error) {
	const q = `INSERT INTO api_permissions (id, tenant_id, api, method, resource, action, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, tenant_id, api, method, resource, action, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRow(ctx, q, id, perm.TenantID, perm.API, perm.Method, perm.Resource, perm.Action, now, now)
	var out APIPermission
	if err := row.Scan(&out.ID, &out.TenantID, &out.API, &out.Method, &out.Resource, &out.Action, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateAPIPermission failed", logger.ErrorField(err), logger.Any("perm", perm))
		return APIPermission{}, err
	}

	return out, nil
}

func (s *PostgresStore) DeleteAPIPermission(ctx context.Context, id string) error {
	const q = `DELETE FROM api_permissions WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	if err != nil {
		s.logger.Error("DeleteAPIPermission failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	return nil
}

func (s *PostgresStore) ListAPIPermissions(ctx context.Context, tenantID, api, method string, page, pageSize int) ([]APIPermission, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, tenant_id, api, method, resource, action, created_at, updated_at FROM api_permissions WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if api != "" {
		q += " AND api = $2"
		args = append(args, api)
	}
	if method != "" {
		q += " AND method = $3"
		args = append(args, method)
	}
	q += " ORDER BY created_at DESC LIMIT $4 OFFSET $5"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListAPIPermissions query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []APIPermission
	for rows.Next() {
		var p APIPermission
		if err := rows.Scan(&p.ID, &p.TenantID, &p.API, &p.Method, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("ListAPIPermissions scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// --- ResourceService ---
func (s *PostgresStore) CreateResource(ctx context.Context, res Resource) (Resource, error) {
	const q = `INSERT INTO resources (id, tenant_id, type, name, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, tenant_id, type, name, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRow(ctx, q, id, res.TenantID, res.Type, res.Name, now, now)
	var out Resource
	if err := row.Scan(&out.ID, &out.TenantID, &out.Type, &out.Name, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateResource failed", logger.ErrorField(err), logger.Any("res", res))
		return Resource{}, err
	}

	return out, nil
}

func (s *PostgresStore) UpdateResource(ctx context.Context, res Resource) (Resource, error) {
	const q = `UPDATE resources SET type = $2, name = $3, updated_at = $4 WHERE id = $1 RETURNING id, tenant_id, type, name, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, res.ID, res.Type, res.Name, time.Now().UTC())
	var out Resource
	if err := row.Scan(&out.ID, &out.TenantID, &out.Type, &out.Name, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdateResource failed", logger.ErrorField(err), logger.Any("res", res))
		return Resource{}, err
	}

	return out, nil
}

func (s *PostgresStore) DeleteResource(ctx context.Context, id string) error {
	const q = `DELETE FROM resources WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	if err != nil {
		s.logger.Error("DeleteResource failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	return nil
}

func (s *PostgresStore) GetResource(ctx context.Context, id string) (Resource, error) {
	const q = `SELECT id, tenant_id, type, name, created_at, updated_at FROM resources WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Resource
	if err := row.Scan(&out.ID, &out.TenantID, &out.Type, &out.Name, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetResource failed", logger.ErrorField(err), logger.String("id", id))
		return Resource{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListResources(ctx context.Context, tenantID, typ string, page, pageSize int) ([]Resource, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, tenant_id, type, name, created_at, updated_at FROM resources WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if typ != "" {
		q += " AND type = $2"
		args = append(args, typ)
	}
	q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListResources query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Resource
	for rows.Next() {
		var r Resource
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Type, &r.Name, &r.CreatedAt, &r.UpdatedAt); err != nil {
			s.logger.Error("ListResources scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, tenantID, actorID, action, resource string, page, pageSize int) ([]AuditLog, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, tenant_id, actor_id, action, resource, target_id, details, created_at FROM audit_logs WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if actorID != "" {
		q += " AND actor_id = $2"
		args = append(args, actorID)
	}
	if action != "" {
		q += " AND action = $3"
		args = append(args, action)
	}
	if resource != "" {
		q += " AND resource = $4"
		args = append(args, resource)
	}
	q += " ORDER BY created_at DESC LIMIT $5 OFFSET $6"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListAuditLogs query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.TenantID, &a.ActorID, &a.Action, &a.Resource, &a.TargetID, &a.Details, &a.CreatedAt); err != nil {
			s.logger.Error("ListAuditLogs scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// RBACService implementation for PostgresStore
// Enforces RBAC for all modules, including project management
func (s *PostgresStore) CheckPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	// Validate input
	if userID == "" || resource == "" || action == "" {
		s.logger.Error("CheckPermission invalid input", logger.String("user_id", userID), logger.String("resource", resource), logger.String("action", action))
		return false, ErrInvalidRBACInput
	}
	// Query for user roles on the resource
	roles, err := s.GetUserRoles(ctx, userID, resource)
	if err != nil {
		s.logger.Error("CheckPermission GetUserRoles failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("resource", resource))
		return false, err
	}
	if len(roles) == 0 {
		s.logger.Error("CheckPermission no roles found", logger.String("user_id", userID), logger.String("resource", resource))
		return false, nil
	}
	// Check if any role grants the permission
	const q = `SELECT COUNT(1) FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN roles r ON r.id = rp.role_id
	WHERE r.name = ANY($1) AND p.resource = $2 AND p.action = $3`
	var count int
	err = s.db.QueryRow(ctx, q, pq.Array(roles), resource, action).Scan(&count)
	if err != nil {
		s.logger.Error("CheckPermission query failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("resource", resource), logger.String("action", action))
		return false, err
	}
	return count > 0, nil
}

func (s *PostgresStore) GetUserRoles(ctx context.Context, userID, resource string) ([]string, error) {
	if userID == "" || resource == "" {
		return nil, ErrInvalidRBACInput
	}
	const q = `SELECT r.name FROM roles r
		JOIN role_bindings rb ON rb.role_id = r.id
		JOIN resources res ON res.id = rb.resource_id
	WHERE rb.user_id = $1 AND res.name = $2`
	rows, err := s.db.Query(ctx, q, userID, resource)
	if err != nil {
		s.logger.Error("GetUserRoles query failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("resource", resource))
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			s.logger.Error("GetUserRoles scan failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("resource", resource))
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

var ErrInvalidRBACInput = errors.New("invalid RBAC input")

// --- ABACPolicyService ---

func (s *PostgresStore) CreateABACPolicy(ctx context.Context, policy ABACPolicy) (ABACPolicy, error) {
	const q = `INSERT INTO abac_policies (id, tenant_id, name, effect, actions, resources, subjects, conditions, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, tenant_id, name, effect, actions, resources, subjects, conditions, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	cond, err := json.Marshal(policy.Conditions)
	if err != nil {
		s.logger.Error("CreateABACPolicy: marshal conditions failed", logger.ErrorField(err))
		return ABACPolicy{}, err
	}
	row := s.db.QueryRow(ctx, q, id, policy.TenantID, policy.Name, policy.Effect, pq.Array(policy.Actions), pq.Array(policy.Resources), pq.Array(policy.Subjects), cond, now, now)
	var out ABACPolicy
	var condRaw []byte
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.Effect, pq.Array(&out.Actions), pq.Array(&out.Resources), pq.Array(&out.Subjects), &condRaw, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateABACPolicy failed", logger.ErrorField(err), logger.Any("policy", policy))
		return ABACPolicy{}, err
	}
	if err := json.Unmarshal(condRaw, &out.Conditions); err != nil {
		s.logger.Error("CreateABACPolicy: unmarshal conditions failed", logger.ErrorField(err))
		return ABACPolicy{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateABACPolicy(ctx context.Context, policy ABACPolicy) (ABACPolicy, error) {
	const q = `UPDATE abac_policies SET name=$2, effect=$3, actions=$4, resources=$5, subjects=$6, conditions=$7, updated_at=$8 WHERE id=$1 RETURNING id, tenant_id, name, effect, actions, resources, subjects, conditions, created_at, updated_at`
	cond, err := json.Marshal(policy.Conditions)
	if err != nil {
		s.logger.Error("UpdateABACPolicy: marshal conditions failed", logger.ErrorField(err))
		return ABACPolicy{}, err
	}
	row := s.db.QueryRow(ctx, q, policy.ID, policy.Name, policy.Effect, pq.Array(policy.Actions), pq.Array(policy.Resources), pq.Array(policy.Subjects), cond, time.Now().UTC())
	var out ABACPolicy
	var condRaw []byte
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.Effect, pq.Array(&out.Actions), pq.Array(&out.Resources), pq.Array(&out.Subjects), &condRaw, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdateABACPolicy failed", logger.ErrorField(err), logger.Any("policy", policy))
		return ABACPolicy{}, err
	}
	if err := json.Unmarshal(condRaw, &out.Conditions); err != nil {
		s.logger.Error("UpdateABACPolicy: unmarshal conditions failed", logger.ErrorField(err))
		return ABACPolicy{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteABACPolicy(ctx context.Context, id string) error {
	const q = `DELETE FROM abac_policies WHERE id=$1`
	_, err := s.db.Exec(ctx, q, id)
	if err != nil {
		s.logger.Error("DeleteABACPolicy failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}

func (s *PostgresStore) GetABACPolicy(ctx context.Context, id string) (ABACPolicy, error) {
	const q = `SELECT id, tenant_id, name, effect, actions, resources, subjects, conditions, created_at, updated_at FROM abac_policies WHERE id=$1`
	row := s.db.QueryRow(ctx, q, id)
	var out ABACPolicy
	var condRaw []byte
	if err := row.Scan(&out.ID, &out.TenantID, &out.Name, &out.Effect, pq.Array(&out.Actions), pq.Array(&out.Resources), pq.Array(&out.Subjects), &condRaw, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetABACPolicy failed", logger.ErrorField(err), logger.String("id", id))
		return ABACPolicy{}, err
	}
	if err := json.Unmarshal(condRaw, &out.Conditions); err != nil {
		s.logger.Error("GetABACPolicy: unmarshal conditions failed", logger.ErrorField(err))
		return ABACPolicy{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListABACPolicies(ctx context.Context, tenantID string, page, pageSize int) ([]ABACPolicy, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, tenant_id, name, effect, actions, resources, subjects, conditions, created_at, updated_at FROM abac_policies WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, q, tenantID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListABACPolicies query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	defer rows.Close()
	var out []ABACPolicy
	for rows.Next() {
		var p ABACPolicy
		var condRaw []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Effect, pq.Array(&p.Actions), pq.Array(&p.Resources), pq.Array(&p.Subjects), &condRaw, &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("ListABACPolicies scan failed", logger.ErrorField(err))
			return nil, err
		}
		if err := json.Unmarshal(condRaw, &p.Conditions); err != nil {
			s.logger.Error("ListABACPolicies: unmarshal conditions failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *PostgresStore) EvaluateABAC(ctx context.Context, input ABACEvaluationInput) (ABACEvaluationResult, error) {
	const q = `SELECT id, effect, actions, resources, subjects, conditions FROM abac_policies WHERE tenant_id=$1`
	rows, err := s.db.Query(ctx, q, input.TenantID)
	if err != nil {
		s.logger.Error("EvaluateABAC query failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return ABACEvaluationResult{}, err
	}
	defer rows.Close()
	var matched []string
	for rows.Next() {
		var id, effect string
		var actions, resources, subjects []string
		var condRaw []byte
		if err := rows.Scan(&id, &effect, pq.Array(&actions), pq.Array(&resources), pq.Array(&subjects), &condRaw); err != nil {
			s.logger.Error("EvaluateABAC scan failed", logger.ErrorField(err))
			return ABACEvaluationResult{}, err
		}
		if !contains(actions, input.Action) {
			continue
		}
		if !contains(resources, input.Resource) {
			continue
		}
		if len(subjects) > 0 && !contains(subjects, input.UserID) {
			continue
		}
		var cond map[string]interface{}
		if err := json.Unmarshal(condRaw, &cond); err != nil {
			continue
		}
		if !evaluateConditions(cond, input.Context) {
			continue
		}
		if effect == "allow" {
			matched = append(matched, id)
		}
	}
	return ABACEvaluationResult{
		Allowed:   len(matched) > 0,
		PolicyIDs: matched,
		Reason:    "matched policies",
	}, nil
}

// --- PolicySimulationService ---

func (s *PostgresStore) SimulatePolicy(ctx context.Context, input PolicySimulationInput) (PolicySimulationResult, error) {
	res, err := s.EvaluateABAC(ctx, ABACEvaluationInput{
		TenantID: input.TenantID,
		UserID:   input.UserID,
		Action:   input.Action,
		Resource: input.Resource,
		Context:  input.Context,
	})
	if err != nil {
		s.logger.Error("SimulatePolicy failed", logger.ErrorField(err))
		return PolicySimulationResult{}, err
	}
	return PolicySimulationResult{
		Allowed:         res.Allowed,
		MatchedPolicies: res.PolicyIDs,
		Reason:          res.Reason,
	}, nil
}

// --- PermissionExplainerService ---

func (s *PostgresStore) ExplainPermission(ctx context.Context, input PermissionExplainInput) (PermissionExplainResult, error) {
	res, err := s.EvaluateABAC(ctx, ABACEvaluationInput{
		TenantID: input.TenantID,
		UserID:   input.UserID,
		Action:   input.Action,
		Resource: input.Resource,
		Context:  map[string]interface{}{},
	})
	if err != nil {
		s.logger.Error("ExplainPermission failed", logger.ErrorField(err))
		return PermissionExplainResult{}, err
	}
	explanation := ""
	if res.Allowed {
		explanation = "Permission granted by policies: " + join(res.PolicyIDs, ", ")
	} else {
		explanation = "No matching ABAC policy found"
	}
	return PermissionExplainResult{
		Allowed:     res.Allowed,
		PolicyIDs:   res.PolicyIDs,
		Explanation: explanation,
	}, nil
}

// --- RoleDelegationService ---

func (s *PostgresStore) DelegateRole(ctx context.Context, input RoleDelegationInput) error {
	const q = `INSERT INTO delegated_roles (id, tenant_id, from_user_id, to_user_id, role_id, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err := s.db.Exec(ctx, q, id, input.TenantID, input.FromUserID, input.ToUserID, input.RoleID, input.ExpiresAt, now, now)
	if err != nil {
		s.logger.Error("DelegateRole failed", logger.ErrorField(err), logger.Any("input", input))
		return err
	}
	return nil
}

func (s *PostgresStore) RevokeDelegatedRole(ctx context.Context, input RoleDelegationInput) error {
	const q = `DELETE FROM delegated_roles WHERE tenant_id=$1 AND from_user_id=$2 AND to_user_id=$3 AND role_id=$4`
	_, err := s.db.Exec(ctx, q, input.TenantID, input.FromUserID, input.ToUserID, input.RoleID)
	if err != nil {
		s.logger.Error("RevokeDelegatedRole failed", logger.ErrorField(err), logger.Any("input", input))
		return err
	}
	return nil
}

func (s *PostgresStore) ListDelegatedRoles(ctx context.Context, tenantID, userID string, page, pageSize int) ([]DelegatedRole, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, tenant_id, from_user_id, to_user_id, role_id, expires_at, created_at, updated_at FROM delegated_roles WHERE tenant_id=$1 AND to_user_id=$2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, q, tenantID, userID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListDelegatedRoles query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("user_id", userID))
		return nil, err
	}
	defer rows.Close()
	var out []DelegatedRole
	for rows.Next() {
		var d DelegatedRole
		if err := rows.Scan(&d.ID, &d.TenantID, &d.FromUserID, &d.ToUserID, &d.RoleID, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			s.logger.Error("ListDelegatedRoles scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// --- helpers ---

func contains(arr []string, v string) bool {
	for _, s := range arr {
		if s == v {
			return true
		}
	}
	return false
}

func join(arr []string, sep string) string {
	if len(arr) == 0 {
		return ""
	}
	out := arr[0]
	for i := 1; i < len(arr); i++ {
		out += sep + arr[i]
	}
	return out
}

func evaluateConditions(conds map[string]interface{}, ctx map[string]interface{}) bool {
	// Simple implementation: all keys in conds must match ctx
	for k, v := range conds {
		if ctx[k] != v {
			return false
		}
	}
	return true
}
