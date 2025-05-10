package rbac_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminRBACRoutes(router fiber.Router, handler *RBACAdminHandler) {
	rbac := router.Group("/rbac-management")

	rbac.Post("/roles", handler.CreateRole)
	rbac.Put("/roles/:id", handler.UpdateRole)
	rbac.Delete("/roles/:id", handler.DeleteRole)
	rbac.Get("/roles/:id", handler.GetRole)
	rbac.Get("/roles", handler.ListRoles)

	rbac.Post("/permissions", handler.CreatePermission)
	rbac.Put("/permissions/:id", handler.UpdatePermission)
	rbac.Delete("/permissions/:id", handler.DeletePermission)
	rbac.Get("/permissions/:id", handler.GetPermission)
	rbac.Get("/permissions", handler.ListPermissions)

	rbac.Post("/role-bindings", handler.CreateRoleBinding)
	rbac.Delete("/role-bindings/:id", handler.DeleteRoleBinding)
	rbac.Get("/role-bindings", handler.ListRoleBindings)

	rbac.Post("/policies", handler.CreatePolicy)
	rbac.Put("/policies/:id", handler.UpdatePolicy)
	rbac.Delete("/policies/:id", handler.DeletePolicy)
	rbac.Get("/policies/:id", handler.GetPolicy)
	rbac.Get("/policies", handler.ListPolicies)

	rbac.Post("/api-permissions", handler.CreateAPIPermission)
	rbac.Delete("/api-permissions/:id", handler.DeleteAPIPermission)
	rbac.Get("/api-permissions", handler.ListAPIPermissions)

	rbac.Post("/resources", handler.CreateResource)
	rbac.Put("/resources/:id", handler.UpdateResource)
	rbac.Delete("/resources/:id", handler.DeleteResource)
	rbac.Get("/resources/:id", handler.GetResource)
	rbac.Get("/resources", handler.ListResources)

	rbac.Post("/audit-logs", handler.CreateAuditLog)
	rbac.Get("/audit-logs", handler.ListAuditLogs)

	rbac.Get("/roles/:id/audit-logs", handler.GetRoleAuditLogs)
	rbac.Get("/permissions/:id/audit-logs", handler.GetPermissionAuditLogs)
	rbac.Get("/policies/:id/audit-logs", handler.GetPolicyAuditLogs)
	rbac.Get("/resources/:id/audit-logs", handler.GetResourceAuditLogs)

	rbac.Get("/all-roles", handler.ListAllRoles)
	rbac.Get("/all-permissions", handler.ListAllPermissions)
	rbac.Get("/all-policies", handler.ListAllPolicies)
	rbac.Get("/all-resources", handler.ListAllResources)
}
