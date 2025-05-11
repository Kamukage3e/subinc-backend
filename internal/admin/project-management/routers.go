package project_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

func projectScopeExtractor(c *fiber.Ctx) (string, string) {
	return "project", c.Get("X-Project-ID")
}

func RegisterAdminProjectRoutes(router fiber.Router, handler *ProjectHandler, jwtSecret string) {
	proj := router.Group(
		"/project-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, projectScopeExtractor),
	)

	proj.Post("/projects/create", handler.CreateProject)
	proj.Put("/projects/update", handler.UpdateProject)
	proj.Delete("/projects/delete", handler.DeleteProject)
	proj.Get("/projects/get", handler.GetProject)
	proj.Get("/projects/list", handler.ListProjects)

	proj.Get("/settings/get", handler.GetSettings)
	proj.Put("/settings/update", handler.UpdateSettings)

}
