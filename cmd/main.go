package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"encoding/base64"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/subinc/subinc-backend/internal/admin"
	"github.com/subinc/subinc-backend/internal/cost/cloud"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/cost/service"
	. "github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
	"github.com/subinc/subinc-backend/internal/project"
	"github.com/subinc/subinc-backend/internal/provisioning"
	"github.com/subinc/subinc-backend/internal/provisioning/terraform"
	"github.com/subinc/subinc-backend/internal/server"
	"github.com/subinc/subinc-backend/internal/server/middleware"
	"github.com/subinc/subinc-backend/internal/user"
	"github.com/subinc/subinc-backend/pkg/jobs"
	"github.com/subinc/subinc-backend/pkg/session"
)

// ErrServerClosed is returned on server graceful close
var ErrServerClosed = errors.New("server closed")

// Initialize logger
var log *Logger

// Adapter to make cloud.CostDataProviderRegistry implement domain.ProviderRegistry

type providerRegistryAdapter struct {
	*cloud.CostDataProviderRegistry
}

func (a *providerRegistryAdapter) GetProvider(ctx context.Context, provider domain.CloudProvider, credentials map[string]string) (interface{}, error) {
	return a.CostDataProviderRegistry.GetProviderAsInterface(ctx, provider, credentials)
}

func main() {
	// Initialize logger
	log = NewProduction()
	defer func() {
		_ = log.Flush()
	}()

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load config (Viper, env and file)
	configureViper(log)

	// Create Redis client with enhanced features
	redisClient, err := server.NewRedisClient(log)
	if err != nil {
		log.Fatal("failed to connect to Redis", ErrorField(err))
	}
	defer redisClient.Close()

	// Initialize Postgres pool
	pgPool, err := server.NewPostgresPool(ctx)
	if err != nil {
		log.Fatal("failed to connect to Postgres", ErrorField(err))
	}
	defer pgPool.Close()

	// Initialize session manager
	sessionManager, err := session.NewSessionManager(redisClient, log, viper.GetString("session.prefix"))
	if err != nil {
		log.Fatal("failed to initialize session manager", ErrorField(err))
	}
	if ttl := viper.GetDuration("session.ttl"); ttl > 0 {
		sessionManager.SetDefaultTTL(ttl)
	}

	// Initialize background job client
	jobClient, err := jobs.NewBackgroundJobClient(redisClient, log)
	if err != nil {
		log.Fatal("failed to initialize background job client", ErrorField(err))
	}
	defer jobClient.Close()

	// Initialize Terraform provisioner
	tfProvisioner := terraform.NewTerraformProvisioner(redisClient, log)

	// Initialize secrets manager
	secretsManager, err := secrets.NewAWSSecretsManager(ctx, log)
	if err != nil {
		log.Fatal("failed to initialize secrets manager", ErrorField(err))
	}
	jwtSecretName := viper.GetString("jwt.secret_name")
	if jwtSecretName == "" {
		jwtSecretName = "subinc-jwt-secret"
	}

	// Initialize background job server if enabled
	var jobServer *jobs.BackgroundJobServer
	if viper.GetBool("jobs.enabled") {
		jobConfig, err := jobs.NewDefaultJobConfig(redisClient, log)
		if err != nil {
			log.Fatal("failed to initialize background job config", ErrorField(err))
		}
		jobServer, err = jobs.NewBackgroundJobServer(jobConfig)
		if err != nil {
			log.Fatal("failed to initialize background job server", ErrorField(err))
		}

		// Register job handlers
		registerJobHandlers(jobServer, log, redisClient, sessionManager, tfProvisioner)

		// Start job server
		go func() {
			if err := jobServer.Start(); err != nil {
				log.Error("job server error", ErrorField(err))
			}
		}()
		defer jobServer.Shutdown()
	}

	// Fiber app with secure defaults
	app := fiber.New(fiber.Config{
		AppName:               "Subinc Cost Management Microservice",
		ServerHeader:          "Fiber",
		DisableStartupMessage: true,
		ErrorHandler:          customErrorHandler(log),
	})

	// Apply global middleware
	configureMiddleware(app, redisClient, log, admin.NewPostgresAdminStore(pgPool))

	// Register Prometheus metrics endpoint
	app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	// Wire up repositories
	costRepo, err := repository.NewPostgresCostRepository(pgPool, log)
	if err != nil {
		log.Fatal("failed to initialize cost repository", ErrorField(err))
	}
	billingRepo, err := repository.NewPostgresBillingRepository(pgPool, log)
	if err != nil {
		log.Fatal("failed to initialize billing repository", ErrorField(err))
	}
	// Discount and coupon services use the correct repository implementations
	discountRepo := billingRepo.(repository.DiscountRepository)
	couponRepo := billingRepo.(repository.CouponRepository)
	discountSvc := service.NewDiscountService(discountRepo, log)
	couponSvc := service.NewCouponService(couponRepo, log)
	// Job queue for cost service: use jobs.NewQueue(redisClient, log) if available, else use jobClient as is
	providerFactory := cloud.NewProviderFactory(log)
	providerRegistry := &providerRegistryAdapter{cloud.NewCostDataProviderRegistry(providerFactory)}
	costJobQueue := jobClient
	costService := service.NewCostService(costRepo, costJobQueue, providerRegistry, log)
	// Cloud provider service
	// Use a 32-byte encryption key from secrets manager (e.g., "cloud-creds-key")
	var encryptionKey []byte
	if viper.GetBool("cloud.disableSecretManager") {
		log.Warn("cloud credential encryption key: using dummy key (secret manager disabled via config)")
		encryptionKey = make([]byte, 32) // 32 zero bytes (not secure, for dev/test only)
	} else {
		encryptionKeyStr, err := secretsManager.GetSecret(ctx, "cloud-creds-key")
		if err != nil || len(encryptionKeyStr) != 44 { // base64-encoded 32 bytes
			log.Fatal("failed to load cloud credential encryption key from secrets manager", ErrorField(err))
		}
		encryptionKey, err = base64.StdEncoding.DecodeString(encryptionKeyStr)
		if err != nil || len(encryptionKey) != 32 {
			log.Fatal("invalid cloud credential encryption key", ErrorField(err))
		}
	}
	credRepo, err := repository.NewCredentialRepository(pgPool, encryptionKey, log)
	if err != nil {
		log.Fatal("failed to initialize credential repository", ErrorField(err))
	}
	cloudProviderService := service.NewCloudProviderService(credRepo, providerFactory, costService, log)
	// Billing service
	billingService := service.NewBillingService(billingRepo, discountSvc, pgPool, log)
	// Get API prefix from config
	apiPrefix := viper.GetString("api.prefix")
	if apiPrefix == "" {
		apiPrefix = "/api/v1"
	}
	// Register all API routes, including provisioning
	server.SetupRoutes(app, apiPrefix, costService, cloudProviderService, billingService, couponSvc, log, tfProvisioner, secretsManager, jwtSecretName, pgPool, costRepo)

	// Project management API wiring
	projectRepo := project.NewPostgresRepository(pgPool)
	projectService := project.NewService(projectRepo)
	projectHandler := project.NewHandler(projectService, log)
	project.RegisterProjectRoutes(app, apiPrefix, projectHandler)

	// User management API wiring
	userStore := user.NewPostgresUserStore(pgPool)
	userHandler := user.NewHandler(userStore, secretsManager, jwtSecretName)
	app.Route(apiPrefix, func(router fiber.Router) {
		userHandler.RegisterRoutes(router)
	})

	// Admin management API wiring
	adminStore := admin.NewPostgresAdminStore(pgPool)
	adminHandler := admin.NewHandler(adminStore)
	adminHandler.RegisterRoutes(app, apiPrefix)

	// Start server in a goroutine
	go func() {
		port := viper.GetString("PORT")
		if port == "" {
			port = "8080"
		}

		log.Info("Server starting", String("port", port), Bool("jobs_enabled", viper.GetBool("jobs.enabled")))

		if err := app.Listen(":" + port); err != nil {
			if err.Error() == "server closed" {
				// Server was closed gracefully
				log.Info("server closed gracefully")
			} else {
				log.Fatal("server failed to start", ErrorField(err))
			}
		}
	}()

	// Handle graceful shutdown
	shutdownGracefully(app, log, cancel)
}

// configureViper sets up the configuration
func configureViper(logger *Logger) {
	// Set config file path
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("./deploy")
	viper.AddConfigPath(".")

	// Automatically load environment variables
	viper.AutomaticEnv()

	// Attempt to read config file
	if err := viper.ReadInConfig(); err != nil {
		logger.Warn("no config file found, relying on env vars", ErrorField(err))
	} else {
		logger.Info("config loaded", String("file", viper.ConfigFileUsed()))
	}

	// Set default values
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("jobs.enabled", true)
	viper.SetDefault("jobs.concurrency", 10)
	viper.SetDefault("cache.prefix", "cache:")
	viper.SetDefault("session.prefix", "session:")
	viper.SetDefault("session.ttl", 24*time.Hour)
	viper.SetDefault("rate_limit.enabled", true)
	viper.SetDefault("rate_limit.max_requests", 100)
	viper.SetDefault("rate_limit.window", time.Minute)
}

// configureMiddleware sets up all middleware for the application
func configureMiddleware(app *fiber.App, redisClient *redis.Client, logger *Logger, adminStore *admin.PostgresAdminStore) {
	// CORS middleware with secure settings
	app.Use(middleware.ConfigureCORS())

	// Security headers middleware
	app.Use(middleware.SecurityHeaders())

	// Request logging middleware
	app.Use(middleware.RequestLogger(logger, adminStore))

	// Distributed rate limiting if enabled
	if viper.GetBool("rate_limit.enabled") {
		app.Use(middleware.IPRateLimiter(
			redisClient,
			logger,
			viper.GetInt("rate_limit.max_requests"),
			viper.GetDuration("rate_limit.window"),
		))
	}
}

// registerJobHandlers registers all background job handlers
func registerJobHandlers(
	jobServer *jobs.BackgroundJobServer,
	logger *Logger,
	redisClient *redis.Client,
	sessionManager *session.SessionManager,
	tfProvisioner *terraform.TerraformProvisioner,
) {
	// Register AWS cost sync handler
	jobServer.RegisterHandler(jobs.TaskSyncAWSCost, func(ctx context.Context, task *asynq.Task) error {
		// Example implementation
		var payload struct {
			TenantID string `json:"tenant_id"`
		}

		if err := jobs.UnmarshalPayload(task, &payload); err != nil {
			return err
		}

		logger.Info("Processing AWS cost sync", String("tenant_id", payload.TenantID))

		// Implement AWS cost sync logic
		// This would typically involve fetching cost data from AWS APIs
		// and storing it in the database

		return nil
	})

	// Register cleanup job
	jobServer.RegisterHandler(jobs.TaskCleanupExpiredData, func(ctx context.Context, task *asynq.Task) error {
		logger.Info("Running expired data cleanup job")

		// Clean expired sessions
		deletedSessions, err := sessionManager.CleanExpiredSessions(ctx)
		if err != nil {
			logger.Error("Failed to clean expired sessions", ErrorField(err))
		} else {
			logger.Info("Cleaned expired sessions", Int("count", deletedSessions))
		}

		// Update session count metrics
		if _, err := sessionManager.GetActiveSessionCount(ctx); err != nil {
			logger.Error("Failed to update session count metrics", ErrorField(err))
		}

		// Perform Redis health check
		if err := jobServer.RedisHealthCheck(ctx, redisClient); err != nil {
			logger.Error("Redis health check failed during cleanup", ErrorField(err))
		}

		// Additional cleanup tasks can be added here
		// - Clean old audit logs
		// - Archive old cost data
		// - Clean temporary files
		// - Run database maintenance

		return nil
	})

	// Schedule recurring jobs
	// These would normally be scheduled in a separate function or file,
	// but we're putting them here for simplicity
	redisOpt := asynq.RedisClientOpt{
		Addr:     redisClient.Options().Addr,
		Password: redisClient.Options().Password,
		DB:       redisClient.Options().DB,
	}

	scheduler := asynq.NewScheduler(redisOpt, &asynq.SchedulerOpts{})

	// Schedule daily AWS cost sync at midnight
	if _, err := scheduler.Register("0 0 * * *", asynq.NewTask(
		jobs.TaskSyncAWSCost,
		nil,
		asynq.Queue(jobs.QueueDefault),
		asynq.MaxRetry(3),
	)); err != nil {
		logger.Error("Failed to schedule AWS cost sync job", ErrorField(err))
	}

	// Schedule hourly cleanup
	if _, err := scheduler.Register("0 * * * *", asynq.NewTask(
		jobs.TaskCleanupExpiredData,
		nil,
		asynq.Queue(jobs.QueueLow),
		asynq.MaxRetry(2),
	)); err != nil {
		logger.Error("Failed to schedule cleanup job", ErrorField(err))
	}

	// Start the scheduler
	go func() {
		if err := scheduler.Run(); err != nil {
			logger.Error("Scheduler error", ErrorField(err))
		}
	}()

	// Register Terraform provision job
	jobServer.RegisterHandler("provision:terraform", func(ctx context.Context, task *asynq.Task) error {
		var payload struct {
			ID      string                         `json:"id"`
			Request *provisioning.ProvisionRequest `json:"request"`
		}
		if err := jobs.UnmarshalPayload(task, &payload); err != nil {
			logger.Error("Failed to unmarshal terraform provision payload", ErrorField(err))
			return err
		}
		status, err := tfProvisioner.GetStatus(ctx, payload.ID)
		if err != nil {
			logger.Error("Failed to get provision status", ErrorField(err), String("id", payload.ID))
			return err
		}
		status.Status = "running"
		status.Message = "Provisioning in progress"
		status.UpdatedAt = time.Now().UTC()
		if err := tfProvisioner.SaveStatus(ctx, status); err != nil {
			logger.Error("Failed to update status to running", ErrorField(err), String("id", payload.ID))
			return err
		}
		err = tfProvisioner.RunProvisionJob(ctx, payload.ID, payload.Request)
		if err != nil {
			status.Status = "failed"
			status.Message = err.Error()
			status.UpdatedAt = time.Now().UTC()
			_ = tfProvisioner.SaveStatus(ctx, status)
			logger.Error("Terraform provision failed", ErrorField(err), String("id", payload.ID))
			return err
		}
		status.Status = "success"
		status.Message = "Provisioning complete"
		status.UpdatedAt = time.Now().UTC()
		if err := tfProvisioner.SaveStatus(ctx, status); err != nil {
			logger.Error("Failed to update status to success", ErrorField(err), String("id", payload.ID))
			return err
		}
		logger.Info("Terraform provision succeeded", String("id", payload.ID))
		return nil
	})
}

// customErrorHandler creates a custom Fiber error handler
func customErrorHandler(logger *Logger) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		// Default status code
		code := fiber.StatusInternalServerError

		// Check if it's a Fiber error
		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
		}

		// Log the error
		logger.Error("request error", String("path", c.Path()), String("method", c.Method()), Int("status", code), ErrorField(err))

		// Don't expose internal errors to the client
		message := "An unexpected error occurred"
		if code < 500 {
			message = err.Error()
		}

		return c.Status(code).JSON(fiber.Map{
			"error":   true,
			"message": message,
			"status":  code,
		})
	}
}

// shutdownGracefully handles graceful shutdown with proper resource cleanup
func shutdownGracefully(app *fiber.App, logger *Logger, cancel context.CancelFunc) {
	// Wait for interrupt signal to gracefully shutdown the server
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive a signal
	sig := <-sigCh
	logger.Info("shutting down server", String("signal", sig.String()))

	// Cancel context to stop any ongoing operations
	cancel()

	// Fiber graceful shutdown
	shutdownTimeout := 5 * time.Second
	if err := app.ShutdownWithTimeout(shutdownTimeout); err != nil {
		logger.Error("error shutting down server", ErrorField(err))
	}

	logger.Info("server gracefully stopped")
}
