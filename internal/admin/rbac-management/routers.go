package rbac_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func rbacScopeExtractor(c *fiber.Ctx) (string, string) {
	return "rbac", c.Get("X-RBAC-ID")
}

// RegisterAdminRBACRoutes allows optional RBAC middleware as a plugin.
func RegisterAdminRBACRoutes(router fiber.Router, handler *RBACHandler, jwtSecretName string, auditLogger security_management.AuditLogger) {
	rbac := router.Group("/rbac-management",
		security_management.OIDCMiddleware(jwtSecretName),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, rbacScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)

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
