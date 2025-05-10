package rbac_management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type RBACAdminHandler struct {
	RoleService          RoleService
	PermissionService    PermissionService
	RoleBindingService   RoleBindingService
	PolicyService        PolicyService
	APIPermissionService APIPermissionService
	ResourceService      ResourceService
	AuditLogService      AuditLogService
	Store                *PostgresStore
}

func (h *RBACAdminHandler) CreateRole(c *fiber.Ctx) error {
	var input Role
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	role, err := h.RoleService.CreateRole(c.Context(), input)
	if err != nil {
		logger.LogError("CreateRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(role)
}

func (h *RBACAdminHandler) UpdateRole(c *fiber.Ctx) error {
	var input Role
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateRole: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	role, err := h.RoleService.UpdateRole(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateRole: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(role)
}

func (h *RBACAdminHandler) DeleteRole(c *fiber.Ctx) error {
	id := c.Params("id")
	tenantID := c.Query("tenant_id")
	if id == "" || tenantID == "" {
		logger.LogError("DeleteRole: id and tenant_id required", logger.String("id", id), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and tenant_id required"})
	}
	if err := h.RoleService.DeleteRole(c.Context(), id, tenantID); err != nil {
		logger.LogError("DeleteRole: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACAdminHandler) GetRole(c *fiber.Ctx) error {
	id := c.Params("id")
	tenantID := c.Query("tenant_id")
	if id == "" || tenantID == "" {
		logger.LogError("GetRole: id and tenant_id required", logger.String("id", id), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and tenant_id required"})
	}
	role, err := h.RoleService.GetRole(c.Context(), id, tenantID)
	if err != nil {
		logger.LogError("GetRole: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(role)
}

func (h *RBACAdminHandler) ListRoles(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	roles, err := h.RoleService.ListRoles(c.Context(), tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListRoles: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"roles": roles, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) CreatePermission(c *fiber.Ctx) error {
	var input Permission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	perm, err := h.PermissionService.CreatePermission(c.Context(), input)
	if err != nil {
		logger.LogError("CreatePermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(perm)
}

func (h *RBACAdminHandler) UpdatePermission(c *fiber.Ctx) error {
	var input Permission
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePermission: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	perm, err := h.PermissionService.UpdatePermission(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePermission: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(perm)
}

func (h *RBACAdminHandler) DeletePermission(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeletePermission: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PermissionService.DeletePermission(c.Context(), id); err != nil {
		logger.LogError("DeletePermission: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACAdminHandler) GetPermission(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPermission: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	perm, err := h.PermissionService.GetPermission(c.Context(), id)
	if err != nil {
		logger.LogError("GetPermission: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(perm)
}

func (h *RBACAdminHandler) ListPermissions(c *fiber.Ctx) error {
	resource := c.Query("resource")
	action := c.Query("action")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	perms, err := h.PermissionService.ListPermissions(c.Context(), resource, action, page, pageSize)
	if err != nil {
		logger.LogError("ListPermissions: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"permissions": perms, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) CreateRoleBinding(c *fiber.Ctx) error {
	var input RoleBinding
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRoleBinding: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	binding, err := h.RoleBindingService.CreateRoleBinding(c.Context(), input)
	if err != nil {
		logger.LogError("CreateRoleBinding: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(binding)
}

func (h *RBACAdminHandler) DeleteRoleBinding(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteRoleBinding: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RoleBindingService.DeleteRoleBinding(c.Context(), id); err != nil {
		logger.LogError("DeleteRoleBinding: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACAdminHandler) ListRoleBindings(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	userID := c.Query("user_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	bindings, err := h.RoleBindingService.ListRoleBindings(c.Context(), tenantID, userID, page, pageSize)
	if err != nil {
		logger.LogError("ListRoleBindings: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"role_bindings": bindings, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) CreatePolicy(c *fiber.Ctx) error {
	var input Policy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	policy, err := h.PolicyService.CreatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("CreatePolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (h *RBACAdminHandler) UpdatePolicy(c *fiber.Ctx) error {
	var input Policy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	policy, err := h.PolicyService.UpdatePolicy(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePolicy: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(policy)
}

func (h *RBACAdminHandler) DeletePolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeletePolicy: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PolicyService.DeletePolicy(c.Context(), id); err != nil {
		logger.LogError("DeletePolicy: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACAdminHandler) GetPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPolicy: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	policy, err := h.PolicyService.GetPolicy(c.Context(), id)
	if err != nil {
		logger.LogError("GetPolicy: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(policy)
}

func (h *RBACAdminHandler) ListPolicies(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	policies, err := h.PolicyService.ListPolicies(c.Context(), tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListPolicies: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"policies": policies, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) CreateAPIPermission(c *fiber.Ctx) error {
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

func (h *RBACAdminHandler) DeleteAPIPermission(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteAPIPermission: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.APIPermissionService.DeleteAPIPermission(c.Context(), id); err != nil {
		logger.LogError("DeleteAPIPermission: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACAdminHandler) ListAPIPermissions(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	api := c.Query("api")
	method := c.Query("method")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	perms, err := h.APIPermissionService.ListAPIPermissions(c.Context(), tenantID, api, method, page, pageSize)
	if err != nil {
		logger.LogError("ListAPIPermissions: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"api_permissions": perms, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) CreateResource(c *fiber.Ctx) error {
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

func (h *RBACAdminHandler) UpdateResource(c *fiber.Ctx) error {
	var input Resource
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateResource: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	res, err := h.ResourceService.UpdateResource(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateResource: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(res)
}

func (h *RBACAdminHandler) DeleteResource(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteResource: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ResourceService.DeleteResource(c.Context(), id); err != nil {
		logger.LogError("DeleteResource: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *RBACAdminHandler) GetResource(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetResource: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	res, err := h.ResourceService.GetResource(c.Context(), id)
	if err != nil {
		logger.LogError("GetResource: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(res)
}

func (h *RBACAdminHandler) ListResources(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	typ := c.Query("type")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	resources, err := h.ResourceService.ListResources(c.Context(), tenantID, typ, page, pageSize)
	if err != nil {
		logger.LogError("ListResources: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"resources": resources, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) CreateAuditLog(c *fiber.Ctx) error {
	var input AuditLog
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAuditLog: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	log, err := h.AuditLogService.CreateAuditLog(c.Context(), input)
	if err != nil {
		logger.LogError("CreateAuditLog: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(log)
}

func (h *RBACAdminHandler) ListAuditLogs(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	actorID := c.Query("actor_id")
	action := c.Query("action")
	resource := c.Query("resource")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.AuditLogService.ListAuditLogs(c.Context(), tenantID, actorID, action, resource, page, pageSize)
	if err != nil {
		logger.LogError("ListAuditLogs: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) GetRoleAuditLogs(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.Store.ListAuditLogs(c.Context(), "", "", "", "role", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) GetPermissionAuditLogs(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.Store.ListAuditLogs(c.Context(), "", "", "", "permission", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) GetPolicyAuditLogs(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.Store.ListAuditLogs(c.Context(), "", "", "", "policy", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) GetResourceAuditLogs(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.Store.ListAuditLogs(c.Context(), "", "", "", "resource", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) ListAllRoles(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	roles, err := h.Store.ListRoles(c.Context(), "", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"roles": roles, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) ListAllPermissions(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	perms, err := h.Store.ListPermissions(c.Context(), "", "", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"permissions": perms, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) ListAllPolicies(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	policies, err := h.Store.ListPolicies(c.Context(), "", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"policies": policies, "page": page, "page_size": pageSize})
}

func (h *RBACAdminHandler) ListAllResources(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	resources, err := h.Store.ListResources(c.Context(), "", "", page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"resources": resources, "page": page, "page_size": pageSize})
}
