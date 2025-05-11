package user_management

import "github.com/gofiber/fiber/v2"

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
