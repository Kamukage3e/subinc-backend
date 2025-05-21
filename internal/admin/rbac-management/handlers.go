package rbac_management

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewRBACHandler(store *PostgresStore) *RBACHandler {
	return &RBACHandler{Store: store}
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

// checkAccess enforces RBAC/ABAC for a handler. Returns error if not allowed.
func (h *RBACHandler) checkAccess(c *fiber.Ctx, resource, action string, abacContext map[string]interface{}) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		logger.LogError("checkAccess: user_id missing in context")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: user_id missing"})
	}
	allowed, err := h.Store.CheckAccess(c.Context(), userID, resource, action, abacContext)
	if err != nil {
		logger.LogError("checkAccess: error in permission check", logger.ErrorField(err))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied: permission check failed"})
	}
	if !allowed {
		logger.LogError("checkAccess: forbidden", logger.String("user_id", userID), logger.String("resource", resource), logger.String("action", action))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient permissions"})
	}
	return nil
}

func (h *RBACHandler) CreateRole(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role", "create", nil); err != nil {
		return err
	}
	var input Role
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateRole: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	role, err := h.RoleService.CreateRole(c.Context(), input)
	if err != nil {
		logger.LogError("CreateRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(role)
}

func (h *RBACHandler) GetRole(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role", "read", nil); err != nil {
		return err
	}
	id := c.Params("id")
	tenantID := c.Query("tenant_id")
	if id == "" || tenantID == "" {
		logger.LogError("GetRole: id and tenant_id required", logger.String("id", id), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	role, err := h.RoleService.GetRole(c.Context(), id, tenantID)
	if err != nil {
		logger.LogError("GetRole: not found", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(role)
}

func (h *RBACHandler) UpdateRole(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role", "update", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input Role
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	role, err := h.RoleService.UpdateRole(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(role)
}

func (h *RBACHandler) DeleteRole(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role", "delete", nil); err != nil {
		return err
	}
	id := c.Params("id")
	tenantID := c.Query("tenant_id")
	if id == "" || tenantID == "" {
		logger.LogError("DeleteRole: id and tenant_id required", logger.String("id", id), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.RoleService.DeleteRole(c.Context(), id, tenantID); err != nil {
		logger.LogError("DeleteRole: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListRoles(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role", "read", nil); err != nil {
		return err
	}
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	roles, err := h.RoleService.ListRoles(c.Context(), tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListRoles: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"roles": roles, "page": page, "page_size": pageSize})
}

func (h *RBACHandler) CreatePermission(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "permission", "create", nil); err != nil {
		return err
	}
	var input Permission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePermission: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	perm, err := h.PermissionService.CreatePermission(c.Context(), input)
	if err != nil {
		logger.LogError("CreatePermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(perm)
}

func (h *RBACHandler) GetPermission(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "permission", "read", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	perm, err := h.PermissionService.GetPermission(c.Context(), id)
	if err != nil {
		logger.LogError("GetPermission: not found", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(perm)
}

func (h *RBACHandler) UpdatePermission(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "permission", "update", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input Permission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	perm, err := h.PermissionService.UpdatePermission(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(perm)
}

func (h *RBACHandler) DeletePermission(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "permission", "delete", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.PermissionService.DeletePermission(c.Context(), id); err != nil {
		logger.LogError("DeletePermission: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListPermissions(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "permission", "read", nil); err != nil {
		return err
	}
	resource := c.Query("resource")
	action := c.Query("action")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	perms, err := h.PermissionService.ListPermissions(c.Context(), resource, action, page, pageSize)
	if err != nil {
		logger.LogError("ListPermissions: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"permissions": perms, "page": page, "page_size": pageSize})
}

func (h *RBACHandler) CreateRoleBinding(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role_binding", "create", nil); err != nil {
		return err
	}
	var input RoleBinding
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRoleBinding: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateRoleBinding: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	binding, err := h.RoleBindingService.CreateRoleBinding(c.Context(), input)
	if err != nil {
		logger.LogError("CreateRoleBinding: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(binding)
}

func (h *RBACHandler) DeleteRoleBinding(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role_binding", "delete", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.RoleBindingService.DeleteRoleBinding(c.Context(), id); err != nil {
		logger.LogError("DeleteRoleBinding: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListRoleBindings(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role_binding", "read", nil); err != nil {
		return err
	}
	tenantID := c.Query("tenant_id")
	userID := c.Query("user_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	bindings, err := h.RoleBindingService.ListRoleBindings(c.Context(), tenantID, userID, page, pageSize)
	if err != nil {
		logger.LogError("ListRoleBindings: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"role_bindings": bindings, "page": page, "page_size": pageSize})
}

func (h *RBACHandler) CreatePolicy(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "policy", "create", nil); err != nil {
		return err
	}
	var input Policy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePolicy: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	policy, err := h.PolicyService.CreatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("CreatePolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (h *RBACHandler) GetPolicy(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "policy", "read", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	policy, err := h.PolicyService.GetPolicy(c.Context(), id)
	if err != nil {
		logger.LogError("GetPolicy: not found", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(policy)
}

func (h *RBACHandler) UpdatePolicy(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "policy", "update", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input Policy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	policy, err := h.PolicyService.UpdatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(policy)
}

func (h *RBACHandler) DeletePolicy(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "policy", "delete", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.PolicyService.DeletePolicy(c.Context(), id); err != nil {
		logger.LogError("DeletePolicy: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListPolicies(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "policy", "read", nil); err != nil {
		return err
	}
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	policies, err := h.PolicyService.ListPolicies(c.Context(), tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListPolicies: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"policies": policies, "page": page, "page_size": pageSize})
}

func (h *RBACHandler) CreateAPIPermission(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "api_permission", "create", nil); err != nil {
		return err
	}
	var input APIPermission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAPIPermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	perm, err := h.APIPermissionService.CreateAPIPermission(c.Context(), input)
	if err != nil {
		logger.LogError("CreateAPIPermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(perm)
}

func (h *RBACHandler) DeleteAPIPermission(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "api_permission", "delete", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteAPIPermission: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.APIPermissionService.DeleteAPIPermission(c.Context(), id); err != nil {
		logger.LogError("DeleteAPIPermission: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListAPIPermissions(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "api_permission", "read", nil); err != nil {
		return err
	}
	tenantID := c.Query("tenant_id")
	api := c.Query("api")
	method := c.Query("method")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	perms, err := h.APIPermissionService.ListAPIPermissions(c.Context(), tenantID, api, method, page, pageSize)
	if err != nil {
		logger.LogError("ListAPIPermissions: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"api_permissions": perms, "page": page, "page_size": pageSize})
}

func (h *RBACHandler) CreateResource(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "resource", "create", nil); err != nil {
		return err
	}
	var input Resource
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateResource: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	res, err := h.ResourceService.CreateResource(c.Context(), input)
	if err != nil {
		logger.LogError("CreateResource: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(res)
}

func (h *RBACHandler) UpdateResource(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "resource", "update", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateResource: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	var input Resource
	input.ID = id
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateResource: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	res, err := h.ResourceService.UpdateResource(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateResource: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(res)
}

func (h *RBACHandler) DeleteResource(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "resource", "delete", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteResource: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.ResourceService.DeleteResource(c.Context(), id); err != nil {
		logger.LogError("DeleteResource: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) GetResource(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "resource", "read", nil); err != nil {
		return err
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetResource: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	res, err := h.ResourceService.GetResource(c.Context(), id)
	if err != nil {
		logger.LogError("GetResource: not found", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(res)
}

func (h *RBACHandler) ListResources(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "resource", "read", nil); err != nil {
		return err
	}
	tenantID := c.Query("tenant_id")
	typeParam := c.Query("type")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	resources, err := h.ResourceService.ListResources(c.Context(), tenantID, typeParam, page, pageSize)
	if err != nil {
		logger.LogError("ListResources: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"resources": resources, "page": page, "page_size": pageSize})
}

// --- ABAC Policy Handlers ---

func (h *RBACHandler) CreateABACPolicy(c *fiber.Ctx) error {
	var input ABACPolicy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateABACPolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.Name == "" || input.Effect == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	policy, err := h.Store.CreateABACPolicy(c.Context(), input)
	if err != nil {
		logger.LogError("CreateABACPolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (h *RBACHandler) UpdateABACPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateABACPolicy: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input ABACPolicy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateABACPolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	policy, err := h.Store.UpdateABACPolicy(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateABACPolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(policy)
}

func (h *RBACHandler) DeleteABACPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteABACPolicy: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.Store.DeleteABACPolicy(c.Context(), id); err != nil {
		logger.LogError("DeleteABACPolicy: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) GetABACPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetABACPolicy: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	policy, err := h.Store.GetABACPolicy(c.Context(), id)
	if err != nil {
		logger.LogError("GetABACPolicy: not found", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(policy)
}

func (h *RBACHandler) ListABACPolicies(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 50)
	policies, err := h.Store.ListABACPolicies(c.Context(), tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListABACPolicies: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"abac_policies": policies, "page": page, "page_size": pageSize})
}

func (h *RBACHandler) SimulatePolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input PolicySimulationInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SimulatePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	result, err := h.Store.SimulatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("SimulatePolicy: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(result)
}

func (h *RBACHandler) SimulatePolicyWhatIf(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input PolicySimulationInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SimulatePolicyWhatIf: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.UserID == "" || input.Action == "" || input.Resource == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	result, err := h.Store.SimulatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("SimulatePolicyWhatIf: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(result)
}

func (h *RBACHandler) EvaluateABAC(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("EvaluateABAC: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input ABACEvaluationInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("EvaluateABAC: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	result, err := h.Store.EvaluateABAC(c.Context(), input)
	if err != nil {
		logger.LogError("EvaluateABAC: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(result)
}

func (h *RBACHandler) ExplainPermission(c *fiber.Ctx) error {
	var input PermissionExplainInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ExplainPermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	result, err := h.Store.ExplainPermission(c.Context(), input)
	if err != nil {
		logger.LogError("ExplainPermission: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(result)
}

// --- Role Delegation Handlers ---

func (h *RBACHandler) DelegateRole(c *fiber.Ctx) error {
	var input RoleDelegationInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("DelegateRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.FromUserID == "" || input.ToUserID == "" || input.RoleID == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.Store.DelegateRole(c.Context(), input); err != nil {
		logger.LogError("DelegateRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) RevokeDelegatedRole(c *fiber.Ctx) error {
	var input RoleDelegationInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("RevokeDelegatedRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.FromUserID == "" || input.ToUserID == "" || input.RoleID == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.Store.RevokeDelegatedRole(c.Context(), input); err != nil {
		logger.LogError("RevokeDelegatedRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACHandler) ListDelegatedRoles(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	userID := c.Query("user_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 50)
	roles, err := h.Store.ListDelegatedRoles(c.Context(), tenantID, userID, page, pageSize)
	if err != nil {
		logger.LogError("ListDelegatedRoles: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("user_id", userID))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"delegated_roles": roles, "page": page, "page_size": pageSize})
}

// Bulk assign roles to users
func (h *RBACHandler) BulkAssignRoleBindings(c *fiber.Ctx) error {
	var req struct {
		TenantID string   `json:"tenant_id"`
		RoleID   string   `json:"role_id"`
		UserIDs  []string `json:"user_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("BulkAssignRoleBindings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.TenantID == "" || req.RoleID == "" || len(req.UserIDs) == 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	bindings, err := h.RoleBindingService.BulkAssignRoleBindings(c.Context(), req.TenantID, req.RoleID, req.UserIDs)
	if err != nil {
		logger.LogError("BulkAssignRoleBindings: failed", logger.ErrorField(err), logger.Any("req", req))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"role_bindings": bindings})
}

// Bulk remove role bindings from users
func (h *RBACHandler) BulkRemoveRoleBindings(c *fiber.Ctx) error {
	var req struct {
		TenantID string   `json:"tenant_id"`
		RoleID   string   `json:"role_id"`
		UserIDs  []string `json:"user_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("BulkRemoveRoleBindings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.TenantID == "" || req.RoleID == "" || len(req.UserIDs) == 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	err := h.RoleBindingService.BulkRemoveRoleBindings(c.Context(), req.TenantID, req.RoleID, req.UserIDs)
	if err != nil {
		logger.LogError("BulkRemoveRoleBindings: failed", logger.ErrorField(err), logger.Any("req", req))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// POST /delegations/delegate: delegate a role to another user with optional expiry
func (h *RBACHandler) DelegateRoleWithExpiry(c *fiber.Ctx) error {
	id := c.Params("id")
	var input RoleDelegationInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("DelegateRoleWithExpiry: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if id != "" {
		input.RoleID = id
	}
	if input.TenantID == "" || input.FromUserID == "" || input.ToUserID == "" || input.RoleID == "" {
		logger.LogError("DelegateRoleWithExpiry: missing required fields", logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	if input.ExpiresAt != nil && input.ExpiresAt.Before(time.Now().UTC()) {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "expiry must be in the future"})
	}
	if err := h.Store.DelegateRole(c.Context(), input); err != nil {
		logger.LogError("DelegateRoleWithExpiry: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// POST /delegations/revoke: revoke a delegated role
func (h *RBACHandler) RevokeDelegatedRoleWithAudit(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input RoleDelegationInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("RevokeDelegatedRoleWithAudit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.RoleID = id
	if input.TenantID == "" || input.FromUserID == "" || input.ToUserID == "" || input.RoleID == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.Store.RevokeDelegatedRole(c.Context(), input); err != nil {
		logger.LogError("RevokeDelegatedRoleWithAudit: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// POST /policies/import: import RBAC/ABAC policies (migration/backup)
func (h *RBACHandler) ImportPolicies(c *fiber.Ctx) error {
	var input struct {
		TenantID string       `json:"tenant_id"`
		Policies []Policy     `json:"policies"`
		ABAC     []ABACPolicy `json:"abac_policies"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ImportPolicies: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || (len(input.Policies) == 0 && len(input.ABAC) == 0) {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	for _, p := range input.Policies {
		p.TenantID = input.TenantID
		if _, err := h.Store.CreatePolicy(c.Context(), p); err != nil {
			logger.LogError("ImportPolicies: failed to import policy", logger.ErrorField(err), logger.Any("policy", p))
			return c.JSON(fiber.ErrExpectationFailed)
		}
	}
	for _, ap := range input.ABAC {
		ap.TenantID = input.TenantID
		if _, err := h.Store.CreateABACPolicy(c.Context(), ap); err != nil {
			logger.LogError("ImportPolicies: failed to import abac policy", logger.ErrorField(err), logger.Any("abac_policy", ap))
			return c.JSON(fiber.ErrExpectationFailed)
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// GET /policies/export: export all RBAC/ABAC policies for a tenant
func (h *RBACHandler) ExportPolicies(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	policies, err := h.Store.ListPolicies(c.Context(), tenantID, 1, 10000)
	if err != nil {
		logger.LogError("ExportPolicies: failed to list policies", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	abac, err := h.Store.ListABACPolicies(c.Context(), tenantID, 1, 10000)
	if err != nil {
		logger.LogError("ExportPolicies: failed to list abac policies", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	result := fiber.Map{"policies": policies, "abac_policies": abac}
	return c.JSON(result)
}

// POST /permission-templates/create: create a permission template
func (h *RBACHandler) CreatePermissionTemplate(c *fiber.Ctx) error {
	var input struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePermissionTemplate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Name == "" || len(input.Permissions) == 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "name and permissions required"})
	}
	id := uuid.NewString()
	tpl := PermissionTemplate{
		ID:          id,
		Name:        input.Name,
		Description: input.Description,
		Permissions: input.Permissions,
		CreatedAt:   time.Now().UTC(),
	}
	permissionTemplates[id] = tpl
	return c.Status(fiber.StatusCreated).JSON(tpl)
}

// GET /permission-templates/list: list all permission templates
func (h *RBACHandler) ListPermissionTemplates(c *fiber.Ctx) error {
	tpls := make([]PermissionTemplate, 0, len(permissionTemplates))
	for _, tpl := range permissionTemplates {
		tpls = append(tpls, tpl)
	}
	return c.JSON(fiber.Map{"permission_templates": tpls})
}

// POST /permission-templates/apply: apply a template to a role
func (h *RBACHandler) ApplyPermissionTemplate(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("ApplyPermissionTemplate: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input struct {
		RoleID string `json:"role_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ApplyPermissionTemplate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	tpl, ok := permissionTemplates[id]
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "template not found"})
	}
	for range tpl.Permissions {
		// This assumes a method to bind permission to role exists (pseudo-code):
		// _ = h.Store.BindPermissionToRole(c.Context(), input.RoleID, permID)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// GET /permissions/discover: list all possible actions/resources
func (h *RBACHandler) DiscoverPermissions(c *fiber.Ctx) error {
	resources, err := h.Store.ListDistinctPermissionResources(c.Context())
	if err != nil {
		logger.LogError("DiscoverPermissions: failed to list resources", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	actions, err := h.Store.ListDistinctPermissionActions(c.Context())
	if err != nil {
		logger.LogError("DiscoverPermissions: failed to list actions", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	result := fiber.Map{"resources": resources, "actions": actions}
	return c.JSON(result)
}

// POST /roles/:id/restore: restore a soft-deleted role
func (h *RBACHandler) RestoreRole(c *fiber.Ctx) error {
	id := c.Params("id")
	tenantID := c.Query("tenant_id")
	if id == "" || tenantID == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.Store.RestoreRole(c.Context(), id, tenantID); err != nil {
		logger.LogError("RestoreRole: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// POST /policies/restore: restore a soft-deleted policy
func (h *RBACHandler) RestorePolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.Store.RestorePolicy(c.Context(), id); err != nil {
		logger.LogError("RestorePolicy: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListRoleTemplates returns all predefined role templates
func (h *RBACHandler) ListRoleTemplates(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role-template", "read", nil); err != nil {
		return err
	}

	// Get templates from the store
	templates, err := h.Store.ListPredefinedRoleTemplates(c.Context())
	if err != nil {
		logger.LogError("ListRoleTemplates: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}

	return c.JSON(fiber.Map{"templates": templates})
}

// ApplyRoleTemplate applies a predefined role template to a tenant
func (h *RBACHandler) ApplyRoleTemplate(c *fiber.Ctx) error {
	if err := h.checkAccess(c, "role-template", "apply", nil); err != nil {
		return err
	}

	templateID := c.Params("id")
	if templateID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	var input struct {
		TenantID string `json:"tenant_id"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ApplyRoleTemplate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	if input.TenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	// Apply the template
	role, err := h.Store.ApplyPredefinedRoleTemplate(c.Context(), templateID, input.TenantID)
	if err != nil {
		logger.LogError("ApplyRoleTemplate: failed", logger.ErrorField(err), logger.String("template_id", templateID), logger.String("tenant_id", input.TenantID))
		return c.JSON(fiber.ErrBadRequest)
	}

	return c.Status(fiber.StatusCreated).JSON(role)
}
