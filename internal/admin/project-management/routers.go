package project_management

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	auditutil "github.com/subinc/subinc-backend/internal/pkg/auditutil"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

func projectScopeExtractor(c *fiber.Ctx) (string, string) {
	return "project", c.Get("X-Project-ID")
}

func RegisterRoutes(router fiber.Router, handler *ProjectHandler, jwtSecret string, auditLogger security_management.AuditLogger) {
	route := router.Group(
		"/project-management",
		security_management.OIDCMiddleware(jwtSecret),
		security_management.NewRateLimitMiddleware(handler.RateLimitService, projectScopeExtractor),
		auditutil.AuditLoggerMiddleware(auditLogger),
	)
	// Projects CRUD
	route.Post("/projects", rbacmiddleware.RBACMiddleware("project", "create", nil), handler.CreateProject)
	route.Get("/projects", rbacmiddleware.RBACMiddleware("project", "read", nil), handler.ListProjects)
	route.Get("/projects/:id", rbacmiddleware.RBACMiddleware("project", "read", nil), handler.GetProject)
	route.Put("/projects/:id", rbacmiddleware.RBACMiddleware("project", "update", nil), handler.UpdateProject)
	route.Delete("/projects/:id", rbacmiddleware.RBACMiddleware("project", "delete", nil), handler.DeleteProject)
	// Settings
	route.Get("/projects/:id/settings", rbacmiddleware.RBACMiddleware("project-settings", "read", nil), handler.GetSettings)
	route.Put("/projects/:id/settings", rbacmiddleware.RBACMiddleware("project-settings", "update", nil), handler.UpdateSettings)
}
