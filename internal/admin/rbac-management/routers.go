package rbac_management

import (
	"github.com/gofiber/fiber/v2"
)

// RegisterAdminRBACRoutes allows optional RBAC middleware as a plugin.
func RegisterAdminRBACRoutes(router fiber.Router, handler *RBACHandler) {
	rbac := router.Group("/rbac-management")

	rbac.Post("/roles/create", handler.CreateRole)
	rbac.Put("/roles/update", handler.UpdateRole)
	rbac.Delete("/roles/delete", handler.DeleteRole)
	rbac.Get("/roles/get", handler.GetRole)
	rbac.Get("/roles/list", handler.ListRoles)

	rbac.Post("/permissions/create", handler.CreatePermission)
	rbac.Put("/permissions/update", handler.UpdatePermission)
	rbac.Delete("/permissions/delete", handler.DeletePermission)
	rbac.Get("/permissions/get", handler.GetPermission)
	rbac.Get("/permissions/list", handler.ListPermissions)

	rbac.Post("/role-bindings/create", handler.CreateRoleBinding)
	rbac.Delete("/role-bindings/delete", handler.DeleteRoleBinding)
	rbac.Get("/role-bindings/list", handler.ListRoleBindings)
	rbac.Post("/role-bindings/bulk-assign", handler.BulkAssignRoleBindings)
	rbac.Delete("/role-bindings/bulk-remove", handler.BulkRemoveRoleBindings)

	rbac.Post("/policies/create", handler.CreatePolicy)
	rbac.Put("/policies/update", handler.UpdatePolicy)
	rbac.Delete("/policies/delete", handler.DeletePolicy)
	rbac.Get("/policies/get", handler.GetPolicy)
	rbac.Get("/policies/list", handler.ListPolicies)
	rbac.Post("/policies/simulate", handler.SimulatePolicyWhatIf)
	rbac.Post("/policies/import", handler.ImportPolicies)
	rbac.Get("/policies/export", handler.ExportPolicies)

	rbac.Post("/api-permissions/create", handler.CreateAPIPermission)
	rbac.Delete("/api-permissions/delete", handler.DeleteAPIPermission)
	rbac.Get("/api-permissions/list", handler.ListAPIPermissions)

	rbac.Post("/resources/create", handler.CreateResource)
	rbac.Put("/resources/update", handler.UpdateResource)
	rbac.Delete("/resources/delete", handler.DeleteResource)
	rbac.Get("/resources/get", handler.GetResource)
	rbac.Get("/resources/list", handler.ListResources)

	rbac.Post("/delegations/delegate", handler.DelegateRoleWithExpiry)
	rbac.Post("/delegations/revoke", handler.RevokeDelegatedRoleWithAudit)

	rbac.Post("/permission-templates/create", handler.CreatePermissionTemplate)
	rbac.Get("/permission-templates/list", handler.ListPermissionTemplates)
	rbac.Post("/permission-templates/apply", handler.ApplyPermissionTemplate)

	rbac.Post("/roles/restore", handler.RestoreRole)
	rbac.Post("/policies/restore", handler.RestorePolicy)
}
