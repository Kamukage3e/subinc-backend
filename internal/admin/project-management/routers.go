package project_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditmiddleware "github.com/subinc/subinc-backend/internal/pkg/auditutil"
)

func projectScopeExtractor(c *fiber.Ctx) (string, string) {
	return "project", c.Get("X-Project-ID")
}

func RegisterRoutes(router fiber.Router, handler *ProjectHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/project-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, projectScopeExtractor),
		auditmiddleware.AuditLoggerMiddleware(auditLogger),
	)
	// Projects CRUD
	route.Post("/projects", handler.CreateProject)
	route.Get("/projects", handler.ListProjects)
	route.Get("/projects/:id", handler.GetProject)
	route.Put("/projects/:id", handler.UpdateProject)
	route.Delete("/projects/:id", handler.DeleteProject)
	// Settings
	route.Get("/projects/:id/settings", handler.GetSettings)
	route.Put("/projects/:id/settings", handler.UpdateSettings)
}
