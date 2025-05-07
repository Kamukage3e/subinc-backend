package project

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(router fiber.Router, deps Deps) {
	projectGroup := router.Group("")
	projectGroup.Post("/projects", deps.ProjectHandler.Create)
	projectGroup.Get("/projects/:id", deps.ProjectHandler.Get)
	projectGroup.Put("/projects/:id", deps.ProjectHandler.Update)
	projectGroup.Delete("/projects/:id", deps.ProjectHandler.Delete)
	projectGroup.Get("/tenants/:tenant_id/projects", deps.ProjectHandler.ListByTenant)
	projectGroup.Get("/orgs/:org_id/projects", deps.ProjectHandler.ListByOrg)
	projectGroup.Patch("/projects/:id/transfer", deps.ProjectHandler.TransferProject)
	projectGroup.Patch("/projects/transfer-user", deps.ProjectHandler.TransferUserToProject)
	projectGroup.Get("/projects/:id/users", deps.ProjectHandler.ListProjectUsers)
	projectGroup.Post("/projects/:id/users", deps.ProjectHandler.AddUserToProject)
	projectGroup.Delete("/projects/:id/users", deps.ProjectHandler.RemoveUserFromProject)
}
