package aws

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/admin"
	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/cost/api"
	"github.com/subinc/subinc-backend/internal/cost/middleware"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
	"github.com/subinc/subinc-backend/internal/project"
	"github.com/subinc/subinc-backend/internal/provisioning"
	"github.com/subinc/subinc-backend/internal/provisioning/terraform"
	"github.com/subinc/subinc-backend/internal/tenant"
	"github.com/subinc/subinc-backend/internal/user"
)

// Deps struct for all handlers and services required for route registration
// All handler dependencies must be injected here for modular, testable, and linter-clean route registration
// Only real, production-grade handlers allowed
// Extend as needed for other domains
type Deps struct {
	UserHandler          *user.UserHandler
	SecretsManager       secrets.SecretsManager
	JWTSecretName        string
	TenantHandler        *tenant.TenantHandler
	ProjectHandler       *project.Handler
	CostHandler          *api.CostHandler
	CloudHandler         *api.CloudHandler
	BillingHandler       *api.BillingHandler
	AdminHandler         *admin.AdminHandler
	TerraformProvisioner *terraform.TerraformProvisioner
	ArchitectureHandler  *architecture.Handler
}

// RegisterRoutes centralizes all route registration for the microservice.
// This enforces modular, SaaS-grade routing boundaries and testability.
func RegisterRoutes(app *fiber.App, apiPrefix string, deps Deps) {
	apiGroup := app.Group(apiPrefix)

	// User routes (public + protected)
	userGroup := apiGroup.Group("/users")
	userGroup.Post("/login", deps.UserHandler.Login)
	userGroup.Post("/register", deps.UserHandler.Register)
	userGroup.Post("/forgot-password", deps.UserHandler.ForgotPassword)
	userGroup.Post("/reset-password", deps.UserHandler.ResetPassword)
	userGroup.Post("/verify-email", deps.UserHandler.VerifyEmail)
	userGroup.Post("/resend-verification", deps.UserHandler.ResendVerification)
	userGroup.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "service": "cost-management"})
	})
	// Authenticated user endpoints
	// AuthMiddleware enforces JWT-based authentication for all /users endpoints below
	authUserGroup := userGroup.Group("", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: deps.SecretsManager,
		JWTSecretName:  deps.JWTSecretName,
	}))
	// RBACMiddleware enforces role-based access control for sensitive user operations
	authUserGroup.Post("/logout", deps.UserHandler.Logout)
	authUserGroup.Post("/refresh", deps.UserHandler.Refresh)
	authUserGroup.Get("/", deps.UserHandler.ListUsers)
	authUserGroup.Get(":id", deps.UserHandler.GetUserByID)
	authUserGroup.Put(":id", deps.UserHandler.UpdateUser)
	authUserGroup.Delete(":id", deps.UserHandler.DeleteUser)
	authUserGroup.Post(":id/roles", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.AssignRole)
	authUserGroup.Delete(":id/roles/:role", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.RemoveRole)
	authUserGroup.Post(":id/attributes", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.SetAttribute)
	authUserGroup.Delete(":id/attributes/:key", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.RemoveAttribute)

	// Tenant routes
	tenantGroup := apiGroup.Group("/tenants")
	tenantGroup.Get("/", deps.TenantHandler.ListTenants)
	tenantGroup.Get(":id", deps.TenantHandler.GetTenantByID)
	tenantGroup.Delete(":id", deps.TenantHandler.DeleteTenant)

	// Project routes
	projectGroup := apiGroup.Group("")
	projectGroup.Post("/projects", deps.ProjectHandler.Create)
	projectGroup.Get("/projects/:id", deps.ProjectHandler.Get)
	projectGroup.Put("/projects/:id", deps.ProjectHandler.Update)
	projectGroup.Delete("/projects/:id", deps.ProjectHandler.Delete)
	projectGroup.Get("/tenants/:tenant_id/projects", deps.ProjectHandler.ListByTenant)
	projectGroup.Get("/orgs/:org_id/projects", deps.ProjectHandler.ListByOrg)

	// Cost routes (with auth middleware)
	costGroup := apiGroup.Group("/cost", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: deps.SecretsManager,
		JWTSecretName:  deps.JWTSecretName,
	}))
	deps.CostHandler.RegisterRoutes(costGroup)
	deps.CloudHandler.RegisterRoutes(costGroup)

	// Billing routes (with auth, logging, and rate limit middleware)
	billingGroup := apiGroup.Group("/billing",
		middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
			SecretsManager: deps.SecretsManager,
			JWTSecretName:  deps.JWTSecretName,
		}),
		middleware.LoggingMiddleware(),
		middleware.RateLimitMiddleware(),
	)
	deps.BillingHandler.RegisterBillingRoutes(billingGroup)

	// Admin routes
	deps.AdminHandler.RegisterRoutes(apiGroup)

	// Provisioning routes
	provGroup := apiGroup.Group("/provisioning")
	provGroup.Post("/terraform", func(c *fiber.Ctx) error {
		var req provisioning.ProvisionRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		status, err := deps.TerraformProvisioner.Provision(c.Context(), &req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusAccepted).JSON(status)
	})
	provGroup.Get("/terraform/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")
		status, err := deps.TerraformProvisioner.GetStatus(c.Context(), id)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(status)
	})
	provGroup.Get("/terraform", func(c *fiber.Ctx) error {
		tenantID := c.Query("tenant_id")
		orgID := c.Query("org_id")
		projectID := c.Query("project_id")
		statuses, err := deps.TerraformProvisioner.List(c.Context(), tenantID, orgID, projectID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(statuses)
	})
	provGroup.Post("/terraform/:id/cancel", func(c *fiber.Ctx) error {
		id := c.Params("id")
		if err := deps.TerraformProvisioner.Cancel(c.Context(), id); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"status": "cancelled"})
	})

	// Architecture routes
	deps.ArchitectureHandler.RegisterRoutes(apiGroup, deps.SecretsManager, deps.JWTSecretName)
}
