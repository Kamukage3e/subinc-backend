package rbac_management

import (
	"github.com/gofiber/fiber/v2"
)


// RBACMiddleware enforces RBAC/ABAC for a given resource/action.
func RBACMiddleware(resource, action string, handler *RBACHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := handler.checkAccess(c, resource, action, nil); err != nil {
			return err
		}
		return c.Next()
	}
}

// RegisterAdminRBACRoutes enforces RBAC/ABAC by default for owner/admin routes.
func RegisterAdminRBACRoutes(router fiber.Router, handler *RBACHandler, jwtSecretName string) {
	rbac := router.Group("/rbac-management") // security_management.OIDCMiddleware(jwtSecretName),

	// Note: Audit logging should be added in main.go to avoid import cycles

	// Roles
	rbac.Post("/roles", RBACMiddleware("role", "create", handler), handler.CreateRole)
	rbac.Get("/roles/:id", RBACMiddleware("role", "read", handler), handler.GetRole)
	rbac.Put("/roles/:id", RBACMiddleware("role", "update", handler), handler.UpdateRole)
	rbac.Delete("/roles/:id", RBACMiddleware("role", "delete", handler), handler.DeleteRole)
	rbac.Get("/roles", RBACMiddleware("role", "read", handler), handler.ListRoles)
	rbac.Post("/roles/:id/restore", RBACMiddleware("role", "restore", handler), handler.RestoreRole)

	// Permissions
	rbac.Post("/permissions", RBACMiddleware("permission", "create", handler), handler.CreatePermission)
	rbac.Get("/permissions/:id", RBACMiddleware("permission", "read", handler), handler.GetPermission)
	rbac.Put("/permissions/:id", RBACMiddleware("permission", "update", handler), handler.UpdatePermission)
	rbac.Delete("/permissions/:id", RBACMiddleware("permission", "delete", handler), handler.DeletePermission)
	rbac.Get("/permissions", RBACMiddleware("permission", "read", handler), handler.ListPermissions)

	// Role bindings
	rbac.Post("/role-bindings", RBACMiddleware("role-binding", "create", handler), handler.CreateRoleBinding)
	rbac.Delete("/role-bindings/:id", RBACMiddleware("role-binding", "delete", handler), handler.DeleteRoleBinding)
	rbac.Get("/role-bindings", RBACMiddleware("role-binding", "read", handler), handler.ListRoleBindings)
	rbac.Post("/role-bindings/bulk-assign", RBACMiddleware("role-binding", "bulk-assign", handler), handler.BulkAssignRoleBindings)
	rbac.Post("/role-bindings/bulk-remove", RBACMiddleware("role-binding", "bulk-remove", handler), handler.BulkRemoveRoleBindings)

	// Policies
	rbac.Post("/policies", RBACMiddleware("policy", "create", handler), handler.CreatePolicy)
	rbac.Put("/policies/:id", RBACMiddleware("policy", "update", handler), handler.UpdatePolicy)
	rbac.Delete("/policies/:id", RBACMiddleware("policy", "delete", handler), handler.DeletePolicy)
	rbac.Get("/policies/:id", RBACMiddleware("policy", "read", handler), handler.GetPolicy)
	rbac.Get("/policies", RBACMiddleware("policy", "read", handler), handler.ListPolicies)
	rbac.Post("/policies/simulate", RBACMiddleware("policy", "simulate", handler), handler.SimulatePolicy)
	rbac.Post("/policies/import", RBACMiddleware("policy", "import", handler), handler.ImportPolicies)
	rbac.Get("/policies/export", RBACMiddleware("policy", "export", handler), handler.ExportPolicies)
	rbac.Post("/policies/:id/restore", RBACMiddleware("policy", "restore", handler), handler.RestorePolicy)
	rbac.Post("/policies/:id/simulate", RBACMiddleware("policy", "simulate", handler), handler.SimulatePolicy)
	rbac.Post("/policies/:id/simulate-what-if", RBACMiddleware("policy", "simulate", handler), handler.SimulatePolicyWhatIf)

	// API permissions
	rbac.Post("/api-permissions", RBACMiddleware("api-permission", "create", handler), handler.CreateAPIPermission)
	rbac.Delete("/api-permissions/:id", RBACMiddleware("api-permission", "delete", handler), handler.DeleteAPIPermission)
	rbac.Get("/api-permissions", RBACMiddleware("api-permission", "read", handler), handler.ListAPIPermissions)

	// Resources
	rbac.Post("/resources", RBACMiddleware("resource", "create", handler), handler.CreateResource)
	rbac.Put("/resources/:id", RBACMiddleware("resource", "update", handler), handler.UpdateResource)
	rbac.Delete("/resources/:id", RBACMiddleware("resource", "delete", handler), handler.DeleteResource)
	rbac.Get("/resources/:id", RBACMiddleware("resource", "read", handler), handler.GetResource)
	rbac.Get("/resources", RBACMiddleware("resource", "read", handler), handler.ListResources)

	// Delegations
	rbac.Post("/delegations", RBACMiddleware("delegation", "create", handler), handler.DelegateRoleWithExpiry)
	rbac.Delete("/delegations/:id", RBACMiddleware("delegation", "delete", handler), handler.RevokeDelegatedRoleWithAudit)
	rbac.Get("/delegations", RBACMiddleware("delegation", "read", handler), handler.ListDelegatedRoles)

	// Permission templates
	rbac.Post("/permission-templates", RBACMiddleware("permission-template", "create", handler), handler.CreatePermissionTemplate)
	rbac.Get("/permission-templates", RBACMiddleware("permission-template", "read", handler), handler.ListPermissionTemplates)
	rbac.Post("/permission-templates/:id/apply", RBACMiddleware("permission-template", "apply", handler), handler.ApplyPermissionTemplate)

	// Role templates - predefined roles with common permission sets
	rbac.Get("/role-templates", RBACMiddleware("role-template", "read", handler), handler.ListRoleTemplates)
	rbac.Post("/role-templates/:id/apply", RBACMiddleware("role-template", "apply", handler), handler.ApplyRoleTemplate)

	// ABAC Policies
	rbac.Post("/abac-policies", RBACMiddleware("abac-policy", "create", handler), handler.CreateABACPolicy)
	rbac.Put("/abac-policies/:id", RBACMiddleware("abac-policy", "update", handler), handler.UpdateABACPolicy)
	rbac.Delete("/abac-policies/:id", RBACMiddleware("abac-policy", "delete", handler), handler.DeleteABACPolicy)
	rbac.Get("/abac-policies/:id", RBACMiddleware("abac-policy", "read", handler), handler.GetABACPolicy)
	rbac.Get("/abac-policies", RBACMiddleware("abac-policy", "read", handler), handler.ListABACPolicies)
	rbac.Post("/abac-policies/:id/evaluate", RBACMiddleware("abac-policy", "evaluate", handler), handler.EvaluateABAC)
}
