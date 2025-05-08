package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"os/signal"
	"strings"
	"syscall"
	"time"

	"database/sql"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/subinc/subinc-backend/enterprise/notifications"
	"github.com/subinc/subinc-backend/internal/admin"
	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/cost/api"
	"github.com/subinc/subinc-backend/internal/cost/cloud"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/email"
	. "github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
	"github.com/subinc/subinc-backend/internal/project"
	"github.com/subinc/subinc-backend/internal/provisioning/terraform"
	"github.com/subinc/subinc-backend/internal/provisioningtypes"
	"github.com/subinc/subinc-backend/internal/server"
	"github.com/subinc/subinc-backend/internal/tenant"
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

// Refactor: Remove all table existence checks from ensureDefaultAdminRBAC
func ensureDefaultAdminRBAC(adminStore *admin.PostgresAdminStore, log *Logger) error {
	// 1. Seed permissions
	builtinPerms := []string{
		"support:view_tickets",
		"support:manage_users",
		"marketing:view_reports",
		"marketing:send_emails",
		"ssm:manage_blogs",
		"ssm:manage_news",
	}
	for _, perm := range builtinPerms {
		id := uuid.NewString()
		err := adminStore.CreatePermission(&admin.AdminPermission{ID: id, Name: perm})
		if err != nil && !strings.Contains(err.Error(), "duplicate") {
			log.Error(fmt.Sprintf("failed to seed admin permission: %s: %v", perm, err))
			return err
		}
	}
	// 2. Seed roles
	roles := []struct {
		Name        string
		Permissions []string
	}{
		{"superuser", builtinPerms},
		{"support", []string{"support:view_tickets", "support:manage_users"}},
		{"marketing", []string{"marketing:view_reports", "marketing:send_emails"}},
		{"ssm", []string{"ssm:manage_blogs", "ssm:manage_news"}},
	}
	for _, role := range roles {
		id := uuid.NewString()
		err := adminStore.CreateRole(&admin.AdminRole{ID: id, Name: role.Name, Permissions: role.Permissions})
		if err != nil && !strings.Contains(err.Error(), "duplicate") {
			log.Error(fmt.Sprintf("failed to seed admin role: %s: %v", role.Name, err))
			return err
		}
	}
	// 3. Ensure at least one admin user exists
	ensureDefaultAdmin(adminStore, log)
	return nil
}

// redactDSN removes password from DSN for logging
func redactDSN(dsn string) string {
	if i := strings.Index(dsn, "@"); i > 0 {
		if j := strings.LastIndex(dsn[:i], ":"); j > 0 {
			return dsn[:j+1] + "***" + dsn[i:]
		}
	}
	return dsn
}

func main() {
	// Initialize logger
	log = NewProduction()
	defer func() {
		_ = log.Flush()
	}()

	// Load config (Viper, env and file)
	configureViper(log)

	// Unify DB DSN for all DB access
	pgDsn, err := server.GetUnifiedDatabaseDSN()
	if err != nil {
		log.Fatal("database DSN not set in config or env", ErrorField(err))
	}
	log.Info("Using database DSN", String("dsn", redactDSN(pgDsn)))

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// Handler wiring
	emailManager := email.NewEmailManager(log)
	userStore := user.NewPostgresUserStore(pgPool)
	encryptionKey := []byte(viper.GetString("encryption.key"))
	credentialRepo, _ := repository.NewCredentialRepository(pgPool, encryptionKey, log)
	costRepo, _ := repository.NewPostgresCostRepository(pgPool, log)
	providerFactory := cloud.NewProviderFactory(log)
	costService := service.NewCostService(costRepo, jobClient, nil, log)
	costHandler := api.NewCostHandler(costService, log)
	cloudProviderService := service.NewCloudProviderService(credentialRepo, providerFactory, costService, log)
	cloudHandler := api.NewCloudHandler(cloudProviderService, log)

	billingRepoImpl, _ := repository.NewPostgresBillingRepository(pgPool, log)
	billingRepoConcrete := billingRepoImpl.(*repository.PostgresBillingRepository)
	discountService := service.NewDiscountService(billingRepoConcrete, log)
	billingService := service.NewBillingService(billingRepoConcrete, discountService, pgPool, log)
	couponService := service.NewCouponService(billingRepoConcrete, log)
	creditService := service.NewCreditService(billingRepoConcrete, log)
	refundService := service.NewRefundService(billingRepoConcrete, log)
	tokenizationRegistry := service.NewTokenizationProviderRegistry(log)
	paymentMethodService := service.NewPaymentMethodService(billingRepoConcrete, log, tokenizationRegistry)
	notifStore := notifications.NewPostgresNotificationStore(pgPool, log)
	subscriptionService := service.NewSubscriptionService(billingRepoConcrete, log, notifStore)
	webhookEventService := service.NewWebhookEventService(billingRepoConcrete, log)
	invoiceAdjustmentService := service.NewInvoiceAdjustmentService(billingRepoConcrete, log)
	billingHandler := api.NewBillingHandler(
		billingService,
		couponService,
		creditService,
		refundService,
		paymentMethodService,
		subscriptionService,
		webhookEventService,
		invoiceAdjustmentService,
		log,
	)
	adminStore := admin.NewPostgresAdminStore(pgPool)
	adminHandler := admin.NewHandler(adminStore, userStore, emailManager, secretsManager, jwtSecretName)
	terraformProvisioner := terraform.NewTerraformProvisioner(redisClient, log)
	architectureRepo := architecture.NewPostgresRepository(pgPool)
	architectureService := architecture.NewService(architectureRepo)
	architectureHandler := architecture.NewHandler(architectureService, *log)

	userHandler := user.NewHandler(userStore, secretsManager, jwtSecretName, emailManager, billingRepoConcrete)
	tenantStore := tenant.NewPostgresTenantStore(pgPool)
	tenantHandler := tenant.NewHandler(tenantStore)
	projectRepo := project.NewPostgresRepository(pgPool)
	projectService := project.NewService(projectRepo)
	projectHandler := project.NewHandler(projectService, log)

	// Get API prefix from config
	apiPrefix := viper.GetString("api.prefix")
	if apiPrefix == "" {
		apiPrefix = "/api/v1"
	}

	// Fiber app with secure defaults and all routes registered
	app := server.SetupRouter(
		apiPrefix,
		pgPool,
		secretsManager,
		jwtSecretName,
		userHandler,
		tenantHandler,
		projectHandler,
		costHandler,
		cloudHandler,
		billingHandler,
		billingRepoConcrete,
		adminHandler,
		terraformProvisioner,
		architectureHandler,
		notifStore,
		adminStore,
		redisClient,
		log,
	)

	// Register login route
	app.Post("/api/v1/login", loginRouterHandler(adminHandler, userHandler))

	// Ensure admin RBAC/seed after all migrations and app setup
	err = ensureDefaultAdminRBAC(adminStore, log)
	if err != nil {
		log.Error("Admin RBAC/seed failed", ErrorField(err))
		os.Exit(1)
	} else {
		log.Info("Admin RBAC/seed completed successfully")
	}

	// Register Prometheus metrics endpoint
	app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

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
			ID      string                              `json:"id"`
			Request *provisioningtypes.ProvisionRequest `json:"request"`
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

func ensureDefaultAdmin(adminStore *admin.PostgresAdminStore, log *Logger) {
	users, err := adminStore.ListUsers()
	if err != nil {
		log.Error("failed to check admin users", ErrorField(err))
		return
	}
	if len(users) > 0 {
		log.Info("admin user(s) already exist, skipping bootstrap")
		return
	}
	adminEmail := viper.GetString("admin.email")
	if adminEmail == "" {
		adminEmail = "admin@subinc.com"
	}
	adminUsername := viper.GetString("admin.username")
	if adminUsername == "" {
		adminUsername = "admin"
	}
	adminPassword := viper.GetString("admin.password")
	if adminPassword == "" {
		adminPassword = generateSecurePassword(32)
	}
	passwordHash, err := user.HashPassword(adminPassword)
	if err != nil {
		log.Error("failed to hash default admin password", ErrorField(err))
		return
	}
	adminUser := &admin.AdminUser{
		ID:           user.GenerateUUID(),
		Username:     adminUsername,
		Email:        adminEmail,
		PasswordHash: passwordHash,
		Roles:        []string{"superuser", "admin"},
	}
	if err := adminStore.CreateUser(adminUser); err != nil {
		log.Error("failed to create default admin user", ErrorField(err))
		return
	}
	log.Warn("Default admin user created. CHANGE THIS PASSWORD IMMEDIATELY.", String("username", adminUsername), String("email", adminEmail), String("password", adminPassword))
}

func generateSecurePassword(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "ChangeMeNow!" // fallback, should never happen
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func debugDBCredsAndSchema(db *sql.DB, log *Logger) {
	var dbName, dbUser, searchPath, version string
	db.QueryRow("SELECT current_database(), current_user, current_setting('search_path'), version()").Scan(&dbName, &dbUser, &searchPath, &version)
	log.Info("DB Debug: Connected", String("db", dbName), String("user", dbUser), String("search_path", searchPath), String("version", version))
	rows, err := db.Query("SELECT schemaname, tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY schemaname, tablename")
	if err != nil {
		log.Error("DB Debug: failed to list tables", ErrorField(err))
		return
	}
	defer rows.Close()
	tables := make([]string, 0)
	for rows.Next() {
		var schema, table string
		_ = rows.Scan(&schema, &table)
		tables = append(tables, schema+"."+table)
	}
	log.Info("DB Debug: visible tables", String("tables", strings.Join(tables, ", ")))
	// Log current roles for the user
	roleRows, err := db.Query("SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'member')")
	if err == nil {
		roles := make([]string, 0)
		for roleRows.Next() {
			var role string
			_ = roleRows.Scan(&role)
			roles = append(roles, role)
		}
		roleRows.Close()
		log.Info("DB Debug: current roles", String("roles", strings.Join(roles, ", ")))
	} else {
		log.Error("DB Debug: failed to list roles", ErrorField(err))
	}
}

func loginRouterHandler(adminHandler *admin.AdminHandler, userHandler *user.UserHandler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&creds); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		var respErr error
		if strings.EqualFold(creds.Username, "admin@subinc.com") {
			respErr = adminHandler.Login(c)
		} else {
			respErr = userHandler.Login(c)
		}
		// After handler, check if response is JSON with token/type, else wrap
		if respErr == nil && c.Response().StatusCode() == fiber.StatusOK {
			var body map[string]interface{}
			if err := c.BodyParser(&body); err == nil {
				token, hasToken := body["token"].(string)
				typeVal, hasType := body["type"].(string)
				if hasToken && hasType {
					return c.Status(fiber.StatusOK).JSON(fiber.Map{"token": token, "type": typeVal})
				}
			}
		}
		return respErr
	}
}
