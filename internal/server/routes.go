package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/admin"
	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/cost/api"
	"github.com/subinc/subinc-backend/internal/email"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
	"github.com/subinc/subinc-backend/internal/project"
	"github.com/subinc/subinc-backend/internal/provisioning"
	"github.com/subinc/subinc-backend/internal/provisioning/terraform"
	"github.com/subinc/subinc-backend/internal/server/middleware"
	
	"github.com/subinc/subinc-backend/internal/tenant"
	"github.com/subinc/subinc-backend/internal/user"
)

// Deps struct for all handlers and services
// This is required for modular, testable, and linter-clean route registration
// All handler dependencies must be injected here
type Deps struct {
	UserHandler          *user.Handler
	TenantHandler        *tenant.TenantHandler
	ProjectHandler       *project.Handler
	CostHandler          *api.CostHandler
	CloudHandler         *api.CloudHandler
	BillingHandler       *api.BillingHandler
	AdminHandler         *admin.AdminHandler
	ArchitectureHandler  *architecture.Handler
	TerraformProvisioner *terraform.TerraformProvisioner
	EmailManager         *email.Manager
	SecretsManager       secrets.SecretsManager
	JWTSecretName        string
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
	authUserGroup := userGroup.Group("", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: deps.SecretsManager,
		JWTSecretName:  deps.JWTSecretName,
	}))
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
	deps.TenantHandler.RegisterRoutes(apiGroup)

	// Project routes
	deps.ProjectHandler.RegisterRoutes(apiGroup)

	// Cost, billing, cloud routes
	costGroup := apiGroup.Group("/cost", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: deps.SecretsManager,
		JWTSecretName:  deps.JWTSecretName,
	}))
	deps.CostHandler.RegisterRoutes(costGroup)
	deps.CloudHandler.RegisterRoutes(costGroup)
	billingGroup := apiGroup.Group("/billing", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: deps.SecretsManager,
		JWTSecretName:  deps.JWTSecretName,
	}), middleware.LoggingMiddleware(), middleware.RateLimitMiddleware())
	deps.BillingHandler.RegisterBillingRoutes(billingGroup)

	// Admin routes
	deps.AdminHandler.RegisterRoutes(apiGroup, "")

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
	deps.ArchitectureHandler.RegisterRoutes(apiGroup)

	// Email management routes
	emailGroup := apiGroup.Group("/email", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: deps.SecretsManager,
		JWTSecretName:  deps.JWTSecretName,
	}))
	deps.EmailManager.RegisterRoutes(emailGroup)
}
