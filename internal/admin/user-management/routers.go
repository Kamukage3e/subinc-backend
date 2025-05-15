package user_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditutil "github.com/subinc/subinc-backend/internal/pkg/auditutil"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func userScopeExtractor(c *fiber.Ctx) (string, string) {
	return "user", c.Get("X-User-ID")
}

// RegisterRoutes registers all user management routes
// Uses RESTful API design principles:
// - Resource collections use plural nouns (e.g., /users)
// - Single resources identified by ID (/users/:id)
// - HTTP method determines action (GET, POST, PUT, DELETE)
// - Nested resources use hierarchical paths (/orgs/:org_id/users)
func RegisterRoutes(router fiber.Router, handler *UserHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/user-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, userScopeExtractor),
		auditutil.AuditLoggerMiddleware(auditLogger),
	)
	// Users resource
	route.Post("/users", rbacmiddleware.RBACMiddleware("user", "create", nil), handler.CreateUser)
	route.Put("/users/:id", rbacmiddleware.RBACMiddleware("user", "update", nil), handler.UpdateUser)
	route.Delete("/users/:id", rbacmiddleware.RBACMiddleware("user", "delete", nil), handler.DeleteUser)
	route.Get("/users/:id", rbacmiddleware.RBACMiddleware("user", "read", nil), handler.GetUser)
	route.Get("/users", rbacmiddleware.RBACMiddleware("user", "read", nil), handler.ListUsers)
	route.Get("/users/by-email/:email", rbacmiddleware.RBACMiddleware("user", "read", nil), handler.GetUserByEmail)

	// User profiles
	route.Post("/users/:user_id/profiles", rbacmiddleware.RBACMiddleware("profile", "create", nil), handler.CreateProfile)
	route.Put("/users/:user_id/profiles", rbacmiddleware.RBACMiddleware("profile", "update", nil), handler.UpdateProfile)
	route.Get("/users/:user_id/profiles", rbacmiddleware.RBACMiddleware("profile", "read", nil), handler.GetProfile)

	// User settings
	route.Get("/users/:user_id/settings", rbacmiddleware.RBACMiddleware("user-settings", "read", nil), handler.GetSettings)
	route.Put("/users/:user_id/settings", rbacmiddleware.RBACMiddleware("user-settings", "update", nil), handler.UpdateSettings)

	// Organization users
	route.Post("/organizations/:org_id/users", rbacmiddleware.RBACMiddleware("org-user", "create", nil), handler.AddUserToOrg)
	route.Delete("/organizations/:org_id/users/:user_id", rbacmiddleware.RBACMiddleware("org-user", "delete", nil), handler.RemoveUserFromOrg)
	route.Get("/organizations/:org_id/users", rbacmiddleware.RBACMiddleware("org-user", "read", nil), handler.ListOrgUsers)
	route.Post("/organizations/:org_id/invites", rbacmiddleware.RBACMiddleware("org-invite", "create", nil), handler.InviteUserToOrg)

	// Project users
	route.Post("/projects/:project_id/users", rbacmiddleware.RBACMiddleware("project-user", "create", nil), handler.AddUserToProject)
	route.Delete("/projects/:project_id/users/:user_id", rbacmiddleware.RBACMiddleware("project-user", "delete", nil), handler.RemoveUserFromProject)
	route.Get("/projects/:project_id/users", rbacmiddleware.RBACMiddleware("project-user", "read", nil), handler.ListProjectUsers)
	route.Post("/projects/:project_id/invites", rbacmiddleware.RBACMiddleware("project-invite", "create", nil), handler.InviteUserToProject)
}
