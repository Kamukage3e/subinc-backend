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
}

