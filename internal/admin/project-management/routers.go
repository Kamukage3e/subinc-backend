package project_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminProjectRoutes(router fiber.Router, handler *ProjectHandler) {
	proj := router.Group("/project-management")

	proj.Post("/projects/create", handler.CreateProject)
	proj.Put("/projects/update", handler.UpdateProject)
	proj.Delete("/projects/delete", handler.DeleteProject)
	proj.Get("/projects/get", handler.GetProject)
	proj.Get("/projects/list", handler.ListProjects)

	proj.Post("/invites/create", handler.CreateInvite)
	proj.Post("/invites/accept", handler.AcceptInvite)
	proj.Delete("/invites/revoke", handler.RevokeInvite)
	proj.Get("/invites/list", handler.ListInvites)
	proj.Get("/invites/search", handler.ListInvites)

	proj.Get("/settings/get", handler.GetSettings)
	proj.Put("/settings/update", handler.UpdateSettings)

}
