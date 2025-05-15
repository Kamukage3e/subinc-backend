package user_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func userScopeExtractor(c *fiber.Ctx) (string, string) {
	return "user", c.Get("X-User-ID")
}

func RegisterAdminUserRoutes(router fiber.Router, handler *UserHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	user := router.Group(
		"/user-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, userScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	user.Post("/users/create", handler.CreateUser)
	user.Put("/users/:id", handler.UpdateUser)
	user.Delete("/users/:id", handler.DeleteUser)
	user.Get("/users/:id", handler.GetUser)
	user.Get("/users/by-email", handler.GetUserByEmail)
	user.Get("/users", handler.ListUsers)

	user.Post("/profiles/create", handler.CreateProfile)
	user.Put("/profiles/:user_id", handler.UpdateProfile)
	user.Get("/profiles/:user_id", handler.GetProfile)

	user.Get("/settings/:user_id", handler.GetSettings)
	user.Put("/settings/:user_id", handler.UpdateSettings)

	user.Put("/orgs/:org_id/users/:user_id", handler.AddUserToOrg)
	user.Delete("/orgs/:org_id/users/:user_id", handler.RemoveUserFromOrg)
	user.Get("/orgs/:org_id/users", handler.ListOrgUsers)
	user.Post("/orgs/:org_id/invite", handler.InviteUserToOrg)

	user.Put("/projects/:project_id/users/:user_id", handler.AddUserToProject)
	user.Delete("/projects/:project_id/users/:user_id", handler.RemoveUserFromProject)
	user.Get("/projects/:project_id/users", handler.ListProjectUsers)
	user.Post("/projects/:project_id/invite", handler.InviteUserToProject)
}
