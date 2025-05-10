package rbac_management

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func getActorID(c *fiber.Ctx) string {
	id := c.Get("X-Actor-ID")
	if id != "" {
		return id
	}
	id = c.Get("X-User-ID")
	if id != "" {
		return id
	}
	return ""
}

func (r *Role) Validate() error {
	if r.TenantID == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "tenant_id must not be empty")
	}
	if r.Name == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "role name must not be empty")
	}
	if len(r.Name) > 128 {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "role name too long")
	}
	return nil
}

func (p *Permission) Validate() error {
	if p.Resource == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "resource must not be empty")
	}
	if p.Action == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "action must not be empty")
	}
	return nil
}

func (b *RoleBinding) Validate() error {
	if b.TenantID == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "tenant_id must not be empty")
	}
	if b.RoleID == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "role_id must not be empty")
	}
	if b.UserID == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "user_id must not be empty")
	}
	return nil
}

func (p *Policy) Validate() error {
	if p.TenantID == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "tenant_id must not be empty")
	}
	if p.Name == "" {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "policy name must not be empty")
	}
	if len(p.Name) > 128 {
		return fiber.NewError(fiber.StatusUnprocessableEntity, "policy name too long")
	}
	return nil
}

func (h *RBACHandler) CreateRole(c *fiber.Ctx) error {
	var input Role
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateRole: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	role, err := h.RoleService.CreateRole(c.Context(), input)
	if err != nil {
		logger.LogError("CreateRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "create_role",
			TargetID:  role.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(role)
}

func (h *RBACHandler) UpdateRole(c *fiber.Ctx) error {
	var input Role
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	role, err := h.RoleService.UpdateRole(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_role",
			TargetID:  role.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(role)
}

func (h *RBACHandler) DeleteRole(c *fiber.Ctx) error {
	var req IDTenantRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("DeleteRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" || req.TenantID == "" {
		logger.LogError("DeleteRole: id and tenant_id required", logger.String("id", req.ID), logger.String("tenant_id", req.TenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and tenant_id required"})
	}
	if err := h.RoleService.DeleteRole(c.Context(), req.ID, req.TenantID); err != nil {
		logger.LogError("DeleteRole: failed", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "delete_role",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) GetRole(c *fiber.Ctx) error {
	var req IDTenantRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("GetRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" || req.TenantID == "" {
		logger.LogError("GetRole: id and tenant_id required", logger.String("id", req.ID), logger.String("tenant_id", req.TenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and tenant_id required"})
	}
	role, err := h.RoleService.GetRole(c.Context(), req.ID, req.TenantID)
	if err != nil {
		logger.LogError("GetRole: not found", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "read_role",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(role)
}

func (h *RBACHandler) ListRoles(c *fiber.Ctx) error {
	var req ListRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("ListRoles: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 100
	}
	roles, err := h.RoleService.ListRoles(c.Context(), req.TenantID, req.Page, req.PageSize)
	if err != nil {
		logger.LogError("ListRoles: failed", logger.ErrorField(err), logger.String("tenant_id", req.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_roles",
			TargetID:  "",
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"roles": roles, "page": req.Page, "page_size": req.PageSize})
}

func (h *RBACHandler) CreatePermission(c *fiber.Ctx) error {
	var input Permission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePermission: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	perm, err := h.PermissionService.CreatePermission(c.Context(), input)
	if err != nil {
		logger.LogError("CreatePermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "create_permission",
			TargetID:  perm.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(perm)
}

func (h *RBACHandler) UpdatePermission(c *fiber.Ctx) error {
	var input Permission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	perm, err := h.PermissionService.UpdatePermission(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_permission",
			TargetID:  perm.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(perm)
}

func (h *RBACHandler) DeletePermission(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("DeletePermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("DeletePermission: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PermissionService.DeletePermission(c.Context(), req.ID); err != nil {
		logger.LogError("DeletePermission: failed", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "delete_permission",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) GetPermission(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("GetPermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("GetPermission: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	perm, err := h.PermissionService.GetPermission(c.Context(), req.ID)
	if err != nil {
		logger.LogError("GetPermission: not found", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "read_permission",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(perm)
}

func (h *RBACHandler) ListPermissions(c *fiber.Ctx) error {
	var req ListPermissionRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("ListPermissions: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 100
	}
	perms, err := h.PermissionService.ListPermissions(c.Context(), req.Resource, req.Action, req.Page, req.PageSize)
	if err != nil {
		logger.LogError("ListPermissions: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_permissions",
			TargetID:  "",
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"permissions": perms, "page": req.Page, "page_size": req.PageSize})
}

func (h *RBACHandler) CreateRoleBinding(c *fiber.Ctx) error {
	var input RoleBinding
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRoleBinding: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateRoleBinding: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	binding, err := h.RoleBindingService.CreateRoleBinding(c.Context(), input)
	if err != nil {
		logger.LogError("CreateRoleBinding: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "create_role_binding",
			TargetID:  binding.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(binding)
}

func (h *RBACHandler) DeleteRoleBinding(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("DeleteRoleBinding: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("DeleteRoleBinding: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RoleBindingService.DeleteRoleBinding(c.Context(), req.ID); err != nil {
		logger.LogError("DeleteRoleBinding: failed", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "delete_role_binding",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListRoleBindings(c *fiber.Ctx) error {
	var req ListRoleBindingRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("ListRoleBindings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 100
	}
	bindings, err := h.RoleBindingService.ListRoleBindings(c.Context(), req.TenantID, req.UserID, req.Page, req.PageSize)
	if err != nil {
		logger.LogError("ListRoleBindings: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_role_bindings",
			TargetID:  "",
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"role_bindings": bindings, "page": req.Page, "page_size": req.PageSize})
}

func (h *RBACHandler) CreatePolicy(c *fiber.Ctx) error {
	var input Policy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePolicy: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	policy, err := h.PolicyService.CreatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("CreatePolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "create_policy",
			TargetID:  policy.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (h *RBACHandler) UpdatePolicy(c *fiber.Ctx) error {
	var input Policy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	policy, err := h.PolicyService.UpdatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_policy",
			TargetID:  policy.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(policy)
}

func (h *RBACHandler) DeletePolicy(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("DeletePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("DeletePolicy: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PolicyService.DeletePolicy(c.Context(), req.ID); err != nil {
		logger.LogError("DeletePolicy: failed", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "delete_policy",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) GetPolicy(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("GetPolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("GetPolicy: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	policy, err := h.PolicyService.GetPolicy(c.Context(), req.ID)
	if err != nil {
		logger.LogError("GetPolicy: not found", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "read_policy",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(policy)
}

func (h *RBACHandler) ListPolicies(c *fiber.Ctx) error {
	var req ListRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("ListPolicies: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 100
	}
	policies, err := h.PolicyService.ListPolicies(c.Context(), req.TenantID, req.Page, req.PageSize)
	if err != nil {
		logger.LogError("ListPolicies: failed", logger.ErrorField(err), logger.String("tenant_id", req.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_policies",
			TargetID:  "",
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"policies": policies, "page": req.Page, "page_size": req.PageSize})
}

func (h *RBACHandler) CreateAPIPermission(c *fiber.Ctx) error {
	var input APIPermission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAPIPermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	perm, err := h.APIPermissionService.CreateAPIPermission(c.Context(), input)
	if err != nil {
		logger.LogError("CreateAPIPermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(perm)
}

func (h *RBACHandler) DeleteAPIPermission(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("DeleteAPIPermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("DeleteAPIPermission: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.APIPermissionService.DeleteAPIPermission(c.Context(), req.ID); err != nil {
		logger.LogError("DeleteAPIPermission: failed", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListAPIPermissions(c *fiber.Ctx) error {
	var req ListAPIPermissionRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("ListAPIPermissions: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 100
	}
	perms, err := h.APIPermissionService.ListAPIPermissions(c.Context(), req.TenantID, req.API, req.Method, req.Page, req.PageSize)
	if err != nil {
		logger.LogError("ListAPIPermissions: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_api_permissions",
			TargetID:  "",
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"api_permissions": perms, "page": req.Page, "page_size": req.PageSize})
}

func (h *RBACHandler) CreateResource(c *fiber.Ctx) error {
	var input Resource
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateResource: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	res, err := h.ResourceService.CreateResource(c.Context(), input)
	if err != nil {
		logger.LogError("CreateResource: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(res)
}

func (h *RBACHandler) UpdateResource(c *fiber.Ctx) error {
	var input Resource
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateResource: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	res, err := h.ResourceService.UpdateResource(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateResource: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_resource",
			TargetID:  res.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(res)
}

func (h *RBACHandler) DeleteResource(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("DeleteResource: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("DeleteResource: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ResourceService.DeleteResource(c.Context(), req.ID); err != nil {
		logger.LogError("DeleteResource: failed", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) GetResource(c *fiber.Ctx) error {
	var req IDRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("GetResource: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.ID == "" {
		logger.LogError("GetResource: id required", logger.String("id", req.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	res, err := h.ResourceService.GetResource(c.Context(), req.ID)
	if err != nil {
		logger.LogError("GetResource: not found", logger.ErrorField(err), logger.String("id", req.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "read_resource",
			TargetID:  req.ID,
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(res)
}

func (h *RBACHandler) ListResources(c *fiber.Ctx) error {
	var req ListResourceRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("ListResources: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 1000 {
		req.PageSize = 100
	}
	resources, err := h.ResourceService.ListResources(c.Context(), req.TenantID, req.Type, req.Page, req.PageSize)
	if err != nil {
		logger.LogError("ListResources: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_resources",
			TargetID:  "",
			Details:   marshalAuditDetails(req),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"resources": resources, "page": req.Page, "page_size": req.PageSize})
}

func marshalAuditDetails(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
