package server

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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

func isDevEnv() bool {
	env := viper.GetString("APP_ENV")
	return env == "dev" || env == "development" || env == "test"
}

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

	// Health check route for liveness/readiness probes
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
	})

	// --- GLOBAL MIDDLEWARE (Order matters for security, logging, and rate limiting) ---
	// 1. Apply CORS middleware globally before any routes
	app.Use(middleware.ConfigureCORS())
	// 2. Apply security headers middleware globally (prevents common web attacks)
	app.Use(middleware.SecurityHeaders())
	// 3. Apply request logging middleware globally (audit, trace, compliance)
	app.Use(middleware.RequestLogger(log, adminStore))
	// 4. Apply distributed rate limiting middleware globally (protects against abuse, DoS)
	if viper.GetBool("rate_limit.enabled") && !isDevEnv() {
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

	// Centralized error handler: always return JSON with code/message, never leak stack traces
	app.Use(func(c *fiber.Ctx) error {
		err := c.Next()
		if err == nil {
			return nil
		}

		status := fiber.StatusInternalServerError
		code := "internal_error"
		msg := "An unexpected error occurred. Please try again later."

		// Extract information for logging
		path := c.Path()
		method := c.Method()
		ip := c.IP()
		reqID := c.Get("X-Request-ID", uuid.NewString())

		response := fiber.Map{
			"error":      msg,
			"code":       code,
			"request_id": reqID,
		}

		// Check for specific error types
		if fe, ok := err.(*fiber.Error); ok {
			status = fe.Code
			msg = fe.Message
			code = "fiber_error"
			response["error"] = msg
			response["code"] = code

			logger.LogError("Fiber error",
				logger.String("path", path),
				logger.String("method", method),
				logger.String("ip", ip),
				logger.String("request_id", reqID),
				logger.Int("status", status),
				logger.String("code", code),
				logger.ErrorField(err))
		} else if ce, ok := err.(interface {
			Code() string
			Message() string
			MarshalJSON() ([]byte, error)
		}); ok {
			// Handle error types with custom JSON marshaling (like AdminError)
			msg = ce.Message()
			code = ce.Code()
			response["error"] = msg
			response["code"] = code

			// Map common error codes to HTTP status codes
			switch code {
			case "not_found":
				status = fiber.StatusNotFound
			case "invalid_input", "validation_error":
				status = fiber.StatusBadRequest
			case "unauthorized", "unauthenticated":
				status = fiber.StatusUnauthorized
			case "forbidden":
				status = fiber.StatusForbidden
			case "conflict":
				status = fiber.StatusConflict
			case "rate_limit_exceeded":
				status = fiber.StatusTooManyRequests
			}

			// Use the custom JSON marshaling
			safeJSON, _ := ce.MarshalJSON()
			var safeMap map[string]interface{}
			if json.Unmarshal(safeJSON, &safeMap) == nil {
				for k, v := range safeMap {
					response[k] = v
				}
			}

			logger.LogError(msg,
				logger.String("path", path),
				logger.String("method", method),
				logger.String("ip", ip),
				logger.String("request_id", reqID),
				logger.Int("status", status),
				logger.String("code", code),
				logger.ErrorField(err))
		} else if ce, ok := err.(interface {
			Code() string
			Message() string
		}); ok {
			// Handle error types that implement Code() and Message() interface
			msg = ce.Message()
			code = ce.Code()
			response["error"] = msg
			response["code"] = code

			// Map common error codes to HTTP status codes
			switch code {
			case "not_found":
				status = fiber.StatusNotFound
			case "invalid_input", "validation_error":
				status = fiber.StatusBadRequest
			case "unauthorized", "unauthenticated":
				status = fiber.StatusUnauthorized
			case "forbidden":
				status = fiber.StatusForbidden
			case "conflict":
				status = fiber.StatusConflict
			case "rate_limit_exceeded":
				status = fiber.StatusTooManyRequests
			}

			logger.LogError(msg,
				logger.String("path", path),
				logger.String("method", method),
				logger.String("ip", ip),
				logger.String("request_id", reqID),
				logger.Int("status", status),
				logger.String("code", code),
				logger.ErrorField(err))
		} else {
			// Handle generic errors - don't expose details to client
			logger.LogError("Unhandled server error",
				logger.String("path", path),
				logger.String("method", method),
				logger.String("ip", ip),
				logger.String("request_id", reqID),
				logger.ErrorField(err))
		}

		// Return JSON response, never include stack traces
		return c.Status(status).JSON(response)
	})

	return app
}
