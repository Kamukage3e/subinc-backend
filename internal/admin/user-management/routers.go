package user_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

func userScopeExtractor(c *fiber.Ctx) (string, string) {
	return "user", c.Get("X-User-ID")
}

func RegisterRoutes(r fiber.Router, h *UserHandler) {
	// User routes
	r.Post("/users/create", h.CreateUser)
	r.Post("/users/update", h.UpdateUser)
	r.Post("/users/delete", h.DeleteUser)
	r.Post("/users/get", h.GetUser)
	r.Post("/users/get-by-email", h.GetUserByEmail)
	r.Post("/users/list", h.ListUsers)

	// UserProfile routes
	r.Post("/profiles/create", h.CreateProfile)
	r.Post("/profiles/update", h.UpdateProfile)
	r.Post("/profiles/get", h.GetProfile)

	// UserSettings routes
	r.Post("/settings/get", h.GetSettings)
	r.Post("/settings/update", h.UpdateSettings)

	// UserSession routes
	r.Post("/sessions/create", h.CreateSession)
	r.Post("/sessions/delete", h.DeleteSession)
	r.Post("/sessions/get", h.GetSession)
	r.Post("/sessions/list", h.ListSessions)

	// Org membership
	r.Post("/orgs/add-user", h.AddUserToOrg)
	r.Post("/orgs/remove-user", h.RemoveUserFromOrg)
	r.Post("/orgs/list-users", h.ListOrgUsers)
	r.Post("/orgs/invite-user", h.InviteUserToOrg)

	// Project membership
	r.Post("/projects/add-user", h.AddUserToProject)
	r.Post("/projects/remove-user", h.RemoveUserFromProject)
	r.Post("/projects/list-users", h.ListProjectUsers)
	r.Post("/projects/invite-user", h.InviteUserToProject)

}

func RegisterAdminUserRoutes(router fiber.Router, handler *UserHandler, jwtSecret string) {
	user := router.Group(
		"/user-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, userScopeExtractor),
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
	user.Post("/sessions/create", handler.CreateSession)
	user.Post("/sessions/delete", handler.DeleteSession)
	user.Post("/sessions/get", handler.GetSession)
	user.Post("/sessions/list", handler.ListSessions)
	user.Post("/orgs/add-user", handler.AddUserToOrg)
	user.Post("/orgs/remove-user", handler.RemoveUserFromOrg)
	user.Post("/orgs/list-users", handler.ListOrgUsers)
	user.Post("/orgs/invite-user", handler.InviteUserToOrg)
	user.Post("/projects/add-user", handler.AddUserToProject)
	user.Post("/projects/remove-user", handler.RemoveUserFromProject)
	user.Post("/projects/list-users", handler.ListProjectUsers)
	user.Post("/projects/invite-user", handler.InviteUserToProject)
}
