package user_management

import "github.com/gofiber/fiber/v2"

func RegisterRoutes(r fiber.Router, h *Handler) {
	// User routes
	r.Post("/users", h.CreateUser)
	r.Put("/users/:id", h.UpdateUser)
	r.Delete("/users/:id", h.DeleteUser)
	r.Get("/users/:id", h.GetUser)
	r.Get("/users/by-email", h.GetUserByEmail)
	r.Get("/users", h.ListUsers)

	// UserProfile routes
	r.Post("/profiles", h.CreateProfile)
	r.Put("/profiles/:user_id", h.UpdateProfile)
	r.Get("/profiles/:user_id", h.GetProfile)

	// UserSettings routes
	r.Get("/settings/:user_id", h.GetSettings)
	r.Put("/settings/:user_id", h.UpdateSettings)

	// UserSession routes
	r.Post("/sessions", h.CreateSession)
	r.Delete("/sessions/:id", h.DeleteSession)
	r.Get("/sessions/:id", h.GetSession)
	r.Get("/sessions", h.ListSessions)

	// UserAuditLog routes
	r.Post("/audit-logs", h.CreateAuditLog)
	r.Get("/audit-logs", h.ListAuditLogs)
}
