package project_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminProjectRoutes(router fiber.Router, handler *ProjectAdminHandler) {
	proj := router.Group("/project-management")

	proj.Post("/projects/create", handler.CreateProject)
	proj.Put("/projects/update/:id", handler.UpdateProject)
	proj.Delete("/projects/delete/:id", handler.DeleteProject)
	proj.Get("/projects/get/:id", handler.GetProject)
	proj.Get("/projects/list", handler.ListProjects)

	proj.Post("/invites/create", handler.CreateInvite)
	proj.Post("/invites/accept", handler.AcceptInvite)
	proj.Delete("/invites/revoke/:id", handler.RevokeInvite)
	proj.Get("/invites/list", handler.ListInvites)
	proj.Get("/invites/search", handler.ListInvites)

	proj.Get("/settings/get", handler.GetSettings)
	proj.Put("/settings/update", handler.UpdateSettings)

}
