package rbac_management

import (
	"github.com/gofiber/fiber/v2"


)

func rbacScopeExtractor(c *fiber.Ctx) (string, string) {
	return "rbac", c.Get("X-RBAC-ID")
}

// RBACMiddleware enforces RBAC/ABAC for all requests. Hot-pluggable for client routes.
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
	rbac := router.Group("/rbac-management",
		// security_management.OIDCMiddleware(jwtSecretName),
		// security_management.NewRateLimitMiddleware(handler.RateLimitService, rbacScopeExtractor),
		// auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)

	rbac.Post("/roles", RBACMiddleware("role", "create", handler), handler.CreateRole)
	rbac.Get("/roles/:id", RBACMiddleware("role", "read", handler), handler.GetRole)
	rbac.Put("/roles/:id", RBACMiddleware("role", "update", handler), handler.UpdateRole)
	rbac.Delete("/roles/:id", RBACMiddleware("role", "delete", handler), handler.DeleteRole)
	rbac.Get("/roles", RBACMiddleware("role", "read", handler), handler.ListRoles)

	rbac.Post("/permissions", RBACMiddleware("permission", "create", handler), handler.CreatePermission)
	rbac.Get("/permissions/:id", RBACMiddleware("permission", "read", handler), handler.GetPermission)
	rbac.Put("/permissions/:id", RBACMiddleware("permission", "update", handler), handler.UpdatePermission)
	rbac.Delete("/permissions/:id", RBACMiddleware("permission", "delete", handler), handler.DeletePermission)
	rbac.Get("/permissions", RBACMiddleware("permission", "read", handler), handler.ListPermissions)

	rbac.Post("/role-bindings", RBACMiddleware("role-binding", "create", handler), handler.CreateRoleBinding)
	rbac.Delete("/role-bindings/:id", RBACMiddleware("role-binding", "delete", handler), handler.DeleteRoleBinding)
	rbac.Get("/role-bindings", RBACMiddleware("role-binding", "read", handler), handler.ListRoleBindings)
	rbac.Post("/role-bindings/bulk-assign", RBACMiddleware("role-binding", "bulk-assign", handler), handler.BulkAssignRoleBindings)
	rbac.Post("/role-bindings/bulk-remove", RBACMiddleware("role-binding", "bulk-remove", handler), handler.BulkRemoveRoleBindings)
	rbac.Post("/roles/:id/restore", RBACMiddleware("role", "restore", handler), handler.RestoreRole)

	rbac.Post("/policies", RBACMiddleware("policy", "create", handler), handler.CreatePolicy)
	rbac.Put("/policies/:id", RBACMiddleware("policy", "update", handler), handler.UpdatePolicy)
	rbac.Delete("/policies/:id", RBACMiddleware("policy", "delete", handler), handler.DeletePolicy)
	rbac.Get("/policies/:id", RBACMiddleware("policy", "read", handler), handler.GetPolicy)
	rbac.Get("/policies", RBACMiddleware("policy", "read", handler), handler.ListPolicies)
	rbac.Post("/policies/simulate", RBACMiddleware("policy", "simulate", handler), handler.SimulatePolicy)
	rbac.Post("/policies/import", RBACMiddleware("policy", "import", handler), handler.ImportPolicies)
	rbac.Get("/policies/export", RBACMiddleware("policy", "export", handler), handler.ExportPolicies)
	rbac.Post("/policies/:id/restore", RBACMiddleware("policy", "restore", handler), handler.RestorePolicy)

	rbac.Post("/api-permissions", RBACMiddleware("api-permission", "create", handler), handler.CreateAPIPermission)
	rbac.Delete("/api-permissions/:id", RBACMiddleware("api-permission", "delete", handler), handler.DeleteAPIPermission)
	rbac.Get("/api-permissions", RBACMiddleware("api-permission", "read", handler), handler.ListAPIPermissions)

	rbac.Post("/resources", RBACMiddleware("resource", "create", handler), handler.CreateResource)
	rbac.Put("/resources/:id", RBACMiddleware("resource", "update", handler), handler.UpdateResource)
	rbac.Delete("/resources/:id", RBACMiddleware("resource", "delete", handler), handler.DeleteResource)
	rbac.Get("/resources/:id", RBACMiddleware("resource", "read", handler), handler.GetResource)
	rbac.Get("/resources", RBACMiddleware("resource", "read", handler), handler.ListResources)

	rbac.Post("/delegations", RBACMiddleware("delegation", "create", handler), handler.DelegateRoleWithExpiry)
	rbac.Delete("/delegations/:id", RBACMiddleware("delegation", "delete", handler), handler.RevokeDelegatedRoleWithAudit)
	rbac.Get("/delegations", RBACMiddleware("delegation", "read", handler), handler.ListDelegatedRoles)

	rbac.Post("/permission-templates", RBACMiddleware("permission-template", "create", handler), handler.CreatePermissionTemplate)
	rbac.Get("/permission-templates", RBACMiddleware("permission-template", "read", handler), handler.ListPermissionTemplates)
	rbac.Post("/permission-templates/:id/apply", RBACMiddleware("permission-template", "apply", handler), handler.ApplyPermissionTemplate)

	// ABAC Policies
	rbac.Post("/roles", handler.CreateRole)
	rbac.Get("/roles/:id", handler.GetRole)
	rbac.Put("/roles/:id", handler.UpdateRole)
	rbac.Delete("/roles/:id", handler.DeleteRole)
	rbac.Get("/roles", handler.ListRoles)

	rbac.Post("/permissions", handler.CreatePermission)
	rbac.Get("/permissions/:id", handler.GetPermission)
	rbac.Put("/permissions/:id", handler.UpdatePermission)
	rbac.Delete("/permissions/:id", handler.DeletePermission)
	rbac.Get("/permissions", handler.ListPermissions)

	rbac.Post("/role-bindings", handler.CreateRoleBinding)
	rbac.Delete("/role-bindings/:id", handler.DeleteRoleBinding)
	rbac.Get("/role-bindings", handler.ListRoleBindings)
	rbac.Post("/role-bindings/bulk-assign", handler.BulkAssignRoleBindings)
	rbac.Post("/role-bindings/bulk-remove", handler.BulkRemoveRoleBindings)
	rbac.Post("/roles/:id/restore", handler.RestoreRole)

	rbac.Post("/policies", handler.CreatePolicy)
	rbac.Put("/policies/:id", handler.UpdatePolicy)
	rbac.Delete("/policies/:id", handler.DeletePolicy)
	rbac.Get("/policies/:id", handler.GetPolicy)
	rbac.Get("/policies", handler.ListPolicies)
	rbac.Post("/policies/simulate", handler.SimulatePolicy)
	rbac.Post("/policies/import", handler.ImportPolicies)
	rbac.Get("/policies/export", handler.ExportPolicies)
	rbac.Post("/policies/:id/restore", handler.RestorePolicy)

	rbac.Post("/api-permissions", handler.CreateAPIPermission)
	rbac.Delete("/api-permissions/:id", handler.DeleteAPIPermission)
	rbac.Get("/api-permissions", handler.ListAPIPermissions)

	rbac.Post("/resources", handler.CreateResource)
	rbac.Put("/resources/:id", handler.UpdateResource)
	rbac.Delete("/resources/:id", handler.DeleteResource)
	rbac.Get("/resources/:id", handler.GetResource)
	rbac.Get("/resources", handler.ListResources)

	rbac.Post("/delegations", handler.DelegateRoleWithExpiry)
	rbac.Delete("/delegations/:id", handler.RevokeDelegatedRoleWithAudit)
	rbac.Get("/delegations", handler.ListDelegatedRoles)

	rbac.Post("/permission-templates", handler.CreatePermissionTemplate)
	rbac.Get("/permission-templates", handler.ListPermissionTemplates)
	rbac.Post("/permission-templates/:id/apply", handler.ApplyPermissionTemplate)

	// ABAC Policies
	rbac.Post("/abac-policies", handler.CreateABACPolicy)
	rbac.Put("/abac-policies/:id", handler.UpdateABACPolicy)
	rbac.Delete("/abac-policies/:id", handler.DeleteABACPolicy)
	rbac.Get("/abac-policies/:id", handler.GetABACPolicy)
	rbac.Get("/abac-policies", handler.ListABACPolicies)
	rbac.Post("/abac-policies/:id/evaluate", handler.EvaluateABAC)

	// Policy Simulation
	rbac.Post("/policies/:id/simulate", handler.SimulatePolicy)

	// Policy Simulation What If
	rbac.Post("/policies/:id/simulate-what-if", handler.SimulatePolicyWhatIf)

	// Policy Import
	rbac.Post("/policies/import", handler.ImportPolicies)

	// Policy Export
	rbac.Get("/policies/export", handler.ExportPolicies)

	// Policy Restore
	rbac.Post("/policies/:id/restore", handler.RestorePolicy)
}
