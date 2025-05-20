package project_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func projectScopeExtractor(c *fiber.Ctx) (string, string) {
	return "project", c.Get("X-Project-ID")
}

func RegisterRoutes(router fiber.Router, handler *ProjectHandler, jwtSecret string) {
	route := router.Group(
		"/projects",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, projectScopeExtractor),
	)
	// Projects CRUD
	route.Post("/", rbacmiddleware.RBACMiddleware("project", "create", nil), handler.CreateProject)
	route.Get("/", rbacmiddleware.RBACMiddleware("project", "read", nil), handler.ListProjects)
	route.Get("/:id", rbacmiddleware.RBACMiddleware("project", "read", nil), handler.GetProject)
	route.Put("/:id", rbacmiddleware.RBACMiddleware("project", "update", nil), handler.UpdateProject)
	route.Delete("/:id", rbacmiddleware.RBACMiddleware("project", "delete", nil), handler.DeleteProject)
	// Settings
	route.Get("/:id/settings", rbacmiddleware.RBACMiddleware("project-settings", "read", nil), handler.GetSettings)
	route.Put("/:id/settings", rbacmiddleware.RBACMiddleware("project-settings", "update", nil), handler.UpdateSettings)
}
