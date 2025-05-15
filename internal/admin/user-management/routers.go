package user_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
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
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	// Users resource
	route.Post("/users", handler.CreateUser)                    // Create user
	route.Put("/users/:id", handler.UpdateUser)                 // Update user
	route.Delete("/users/:id", handler.DeleteUser)              // Delete user
	route.Get("/users/:id", handler.GetUser)                    // Get user by ID
	route.Get("/users", handler.ListUsers)                      // List/search users
	route.Get("/users/by-email/:email", handler.GetUserByEmail) // Get user by email

	// User profiles
	route.Post("/users/:user_id/profiles", handler.CreateProfile) // Create profile
	route.Put("/users/:user_id/profiles", handler.UpdateProfile)  // Update profile
	route.Get("/users/:user_id/profiles", handler.GetProfile)     // Get profile

	// User settings
	route.Get("/users/:user_id/settings", handler.GetSettings)    // Get settings
	route.Put("/users/:user_id/settings", handler.UpdateSettings) // Update settings

	// Organization users
	route.Post("/organizations/:org_id/users", handler.AddUserToOrg)                 // Add user to org
	route.Delete("/organizations/:org_id/users/:user_id", handler.RemoveUserFromOrg) // Remove user from org
	route.Get("/organizations/:org_id/users", handler.ListOrgUsers)                  // List org users
	route.Post("/organizations/:org_id/invites", handler.InviteUserToOrg)            // Invite user to org

	// Project users
	route.Post("/projects/:project_id/users", handler.AddUserToProject)                 // Add user to project
	route.Delete("/projects/:project_id/users/:user_id", handler.RemoveUserFromProject) // Remove user from project
	route.Get("/projects/:project_id/users", handler.ListProjectUsers)                  // List project users
	route.Post("/projects/:project_id/invites", handler.InviteUserToProject)            // Invite user to project
}
