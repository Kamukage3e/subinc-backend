package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/subinc/subinc-backend/enterprise/notifications"
	"github.com/subinc/subinc-backend/internal/admin"
	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/billing"
	"github.com/subinc/subinc-backend/internal/cost/api"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
	"github.com/subinc/subinc-backend/internal/project"
	"github.com/subinc/subinc-backend/internal/provisioning"
	"github.com/subinc/subinc-backend/internal/provisioning/terraform"
	"github.com/subinc/subinc-backend/internal/server/middleware"
	"github.com/subinc/subinc-backend/internal/tenant"
	"github.com/subinc/subinc-backend/internal/user"
	// Add other handler imports as needed (user, tenant, admin, etc)
)

// SetupRouter centralizes all route registration for the microservice.
// This enforces modular, SaaS-grade routing boundaries and testability.
func SetupRouter(
	apiPrefix string,
	db *pgxpool.Pool,
	secretsManager secrets.SecretsManager,
	jwtSecretName string,
	userHandler *user.UserHandler,
	tenantHandler *tenant.TenantHandler,
	projectHandler *project.Handler,
	costHandler *api.CostHandler,
	cloudHandler *api.CloudHandler,
	billingHandler *api.BillingHandler,
	billingRepo repository.BillingRepository,
	adminHandler *admin.AdminHandler,
	terraformProvisioner *terraform.TerraformProvisioner,
	architectureHandler *architecture.Handler,
	notifStore *notifications.PostgresNotificationStore,
	adminStore *admin.PostgresAdminStore,
	redisClient *redis.Client,
	log *logger.Logger,
) *fiber.App {
	app := fiber.New()

	// --- GLOBAL MIDDLEWARE (Order matters for security, logging, and rate limiting) ---
	// 1. Apply CORS middleware globally before any routes
	app.Use(middleware.ConfigureCORS())
	// 2. Apply security headers middleware globally (prevents common web attacks)
	app.Use(middleware.SecurityHeaders())
	// 3. Apply request logging middleware globally (audit, trace, compliance)
	app.Use(middleware.RequestLogger(log, adminStore))
	// 4. Apply distributed rate limiting middleware globally (protects against abuse, DoS)
	if viper.GetBool("rate_limit.enabled") {
		app.Use(middleware.IPRateLimiter(redisClient, log, viper.GetInt("rate_limit.max_requests"), viper.GetDuration("rate_limit.window")))
	}
	// --- END GLOBAL MIDDLEWARE ---

	// Create API group for all routes
	apiGroup := app.Group(apiPrefix)

	// User routes
	user.RegisterRoutes(apiGroup, user.Deps{
		UserHandler:    userHandler,
		SecretsManager: secretsManager,
		JWTSecretName:  jwtSecretName,
		BillingRepo:    billingRepo,
	})

	// Tenant routes
	tenant.RegisterRoutes(apiGroup, tenant.Deps{
		TenantHandler: tenantHandler,
	})

	// Project routes
	project.RegisterRoutes(apiGroup, project.Deps{
		ProjectHandler: projectHandler,
	})

	// Cost and cloud routes
	costHandler.RegisterRoutes(apiGroup.Group("/cost"))
	cloudHandler.RegisterRoutes(apiGroup.Group("/cost"))

	// Billing routes
	billing.RegisterRoutes(apiGroup.Group("/billing"), billingHandler)

	// Admin routes
	admin.RegisterRoutes(apiGroup, adminHandler)
	admin.RegisterRoutes(app, adminHandler)

	// Provisioning routes
	provisioning.RegisterRoutes(apiGroup.Group("/provisioning"), provisioning.Deps{
		TerraformProvisioner: terraformProvisioner,
	})

	// Architecture routes
	architectureHandler.RegisterRoutes(apiGroup.Group("/architecture"), secretsManager, jwtSecretName)

	return app
}
