package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/admin"
	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/cost/api"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
	"github.com/subinc/subinc-backend/internal/provisioning"
	"github.com/subinc/subinc-backend/internal/provisioning/terraform"
	// Add other handler imports as needed (user, tenant, admin, etc)
)

// SetupRoutes centralizes all route registration for the microservice.
// This enforces modular, SaaS-grade routing boundaries and testability.
func SetupRoutes(app *fiber.App, apiPrefix string, costService service.CostService, cloudProviderService service.CloudProviderService, billingService service.BillingService, couponService service.CouponService, log *logger.Logger, tfProvisioner *terraform.TerraformProvisioner, secretsManager secrets.SecretsManager, jwtSecretName string, db *pgxpool.Pool) {
	// API group
	apiGroup := app.Group(apiPrefix)

	// Cost routes
	costRouter := api.NewRouter(app, apiPrefix, costService, cloudProviderService, billingService, couponService, log, secretsManager, jwtSecretName)
	costRouter.SetupRoutes()

	// Admin routes (modular, production-grade)
	adminStore := admin.NewPostgresAdminStore(db)
	adminHandler := admin.NewHandler(adminStore)
	adminHandler.RegisterRoutes(apiGroup, "")

	// Provisioning routes
	provGroup := apiGroup.Group("/provisioning")
	provGroup.Post("/terraform", func(c *fiber.Ctx) error {
		var req provisioning.ProvisionRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		status, err := tfProvisioner.Provision(c.Context(), &req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		// Enqueue async job (production: use jobs client, here just return status)
		return c.Status(fiber.StatusAccepted).JSON(status)
	})
	provGroup.Get("/terraform/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")
		status, err := tfProvisioner.GetStatus(c.Context(), id)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(status)
	})
	provGroup.Get("/terraform", func(c *fiber.Ctx) error {
		tenantID := c.Query("tenant_id")
		orgID := c.Query("org_id")
		projectID := c.Query("project_id")
		statuses, err := tfProvisioner.List(c.Context(), tenantID, orgID, projectID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(statuses)
	})
	provGroup.Post("/terraform/:id/cancel", func(c *fiber.Ctx) error {
		id := c.Params("id")
		if err := tfProvisioner.Cancel(c.Context(), id); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"status": "cancelled"})
	})

	// Architecture Docs & Diagrams
	archRepo := architecture.NewPostgresRepository(db)
	archService := architecture.NewService(archRepo)
	archHandler := architecture.NewHandler(archService)
	archHandler.RegisterRoutes(apiGroup.Group("/architecture"))

	// Health check (if not already in costRouter)
	apiGroup.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "service": "cost-management"})
	})
}

func SetupRouter( /* ... existing params ... */ db *pgxpool.Pool) *fiber.App {
	app := fiber.New( /* ... */ )
	// ... existing route setup ...

	// Architecture Docs & Diagrams
	archRepo := architecture.NewPostgresRepository(db)
	archService := architecture.NewService(archRepo)
	archHandler := architecture.NewHandler(archService)
	archHandler.RegisterRoutes(app.Group("/api"))

	// ... existing route setup ...
	return app
}
