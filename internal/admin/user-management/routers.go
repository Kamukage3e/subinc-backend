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
	user.Post("/users/update", handler.UpdateUser)
	user.Post("/users/delete", handler.DeleteUser)
	user.Post("/users/get", handler.GetUser)
	user.Post("/users/get-by-email", handler.GetUserByEmail)
	user.Post("/users/list", handler.ListUsers)

	user.Post("/profiles/create", handler.CreateProfile)
	user.Post("/profiles/update", handler.UpdateProfile)
	user.Post("/profiles/get", handler.GetProfile)

	user.Post("/settings/get", handler.GetSettings)
	user.Post("/settings/update", handler.UpdateSettings)

	user.Post("/orgs/add-user", handler.AddUserToOrg)
	user.Post("/orgs/remove-user", handler.RemoveUserFromOrg)
	user.Post("/orgs/list-users", handler.ListOrgUsers)
	user.Post("/orgs/invite-user", handler.InviteUserToOrg)

	user.Post("/projects/add-user", handler.AddUserToProject)
	user.Post("/projects/remove-user", handler.RemoveUserFromProject)
	user.Post("/projects/list-users", handler.ListProjectUsers)
	user.Post("/projects/invite-user", handler.InviteUserToProject)
}
