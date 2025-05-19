package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	// "github.com/graphql-go/graphql"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	billing_management "github.com/subinc/subinc-backend/internal/admin/billing-management"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/discount"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/fee"
	payment "github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/subscription"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/tax"
	organization_management "github.com/subinc/subinc-backend/internal/admin/organization-management"
	project_management "github.com/subinc/subinc-backend/internal/admin/project-management"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"

	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	"github.com/subinc/subinc-backend/internal/pkg/auth"
	jwtProvider "github.com/subinc/subinc-backend/internal/pkg/auth/providers/jwt"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/pkg/rbac"
	"github.com/subinc/subinc-backend/pkg/session"
)

// Global state for DB pool and audit logger, protected by mutex for thread safety
var (
	dbState struct {
		pool        *pgxpool.Pool
		auditLogger security_management.AuditLogger
	}
	dbStateMu = &sync.RWMutex{}
)

// Handler dependencies struct for dynamic DB and audit logger
// Each handler gets a pointer to this struct and reads db/audit logger at request time

type HandlerDeps struct {
	GetDBPool      func() *pgxpool.Pool
	GetAuditLogger func() security_management.AuditLogger
}

// DynamicStore implements the same interface as PostgresStore but always uses the latest dbState
// This allows handlers to always use the current DB pool and audit logger after /db/connect

type DynamicStore struct{}

// RBAC
func (s *DynamicStore) DB() *pgxpool.Pool {
	return getDBPool()
}
func (s *DynamicStore) AuditLogger() security_management.AuditLogger {
	return getAuditLogger()
}

// Helper: extract DB credentials from headers
func extractDBConfig(c *fiber.Ctx) (string, error) {
	host := c.Get("X-DB-Host")
	port := c.Get("X-DB-Port")
	user := c.Get("X-DB-User")
	password := c.Get("X-DB-Password")
	dbname := c.Get("X-DB-Name")
	sslmode := c.Get("X-DB-SSLMode")
	if host == "" || port == "" || user == "" || password == "" || dbname == "" || sslmode == "" {
		return "", fmt.Errorf("missing DB credentials")
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, password, host, port, dbname, sslmode), nil
}

// Middleware: inject *PostgresStore into context for each request
// func withDB(next fiber.Handler) fiber.Handler {
// 	return func(c *fiber.Ctx) error {
// 		dbURL, err := extractDBConfig(c)
// 		if err != nil {
// 			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid DB credentials"})
// 		}
// 		dbpool, err := pgxpool.New(context.Background(), dbURL)
// 		if err != nil {
// 			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB connect failed"})
// 		}
// 		defer dbpool.Close()
// 		store := &rbac_management.PostgresStore{DB: dbpool, AuditLogger: &security_management.PostgresStore{DB: dbpool}}
// 		c.Locals("rbacStore", store)
// 		return next(c)
// 	}
// }

// @title           Subinc Admin API
// @version         1.0
// @description     Unified admin API for Subinc platform (owner + client)
// @contact.name    Subinc Dev Team
// @contact.email   dev@subinc.com
// @license.name    MIT
// @license.url     https://opensource.org/licenses/MIT
// @host            localhost:8080
// @BasePath        /api/v1
// @schemes         http
func main() {

	ownerDBDSN := "postgres://postgres:postgres@localhost:5432/subinc"
	if ownerDBDSN == "" {
		log.Fatalf("OWNER_DB_DSN env var required for DB bootstrap")
	}
	ownerDBPool, err := pgxpool.New(context.Background(), ownerDBDSN)
	if err != nil {
		log.Fatalf("Failed to connect to owner DB: %v", err)
	}
	defer ownerDBPool.Close()

	ctx := context.Background()
	serverConfigStore := server_config.NewStore(ownerDBPool, logger.NewProduction(logger.InfoLevel, "json", false, "owner", "prod"))
	serverConfigService := server_config.NewService(serverConfigStore, 30*time.Second, &security_management.PostgresStore{DB: ownerDBPool})

	logCfg, err := serverConfigService.GetOwnerLoggingConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load logging config: %v", err)
	}
	logr := logger.NewProduction(logger.InfoLevel, logCfg.Format, logCfg.Color, logCfg.Service, logCfg.Env)

	jwtCfg, err := serverConfigService.GetOwnerJWTSecretConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load JWT secret config: %v", err)
	}

	_, err = serverConfigService.GetOwnerGraphQLConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load GraphQL config: %v", err)
	}

	serverPort := os.Getenv("PORT")
	if serverPort == "" {
		serverPort = "8080"
	}

	app := fiber.New()

	// Add a health check endpoint
	app.Get("/api/v1/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"time":    time.Now().Format(time.RFC3339),
			"service": "subinc-backend",
		})
	})

	// Log every request to stdout
	app.Use(func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		latency := time.Since(start)
		logr.Info("request",
			logger.String("method", c.Method()),
			logger.String("path", c.OriginalURL()),
			logger.Int("status", c.Response().StatusCode()),
			logger.String("ip", c.IP()),
			logger.Duration("latency", latency),
		)
		return err
	})

	// Add CORS middleware for development
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", "*")
		c.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS,PATCH")
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Tenant-ID")
		c.Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if c.Method() == "OPTIONS" {
			return c.SendStatus(fiber.StatusNoContent)
		}

		return c.Next()
	})

	// Create RBAC store before any route registration
	store := &rbac_management.PostgresStore{DB: ownerDBPool}
	rbac_management.InitGlobalRBACStore(store)

	// --- Unified admin routes (owner + client) ---
	adminAPI := app.Group("/api/v1/")
	securityStore := security_management.NewPostgresStore(ownerDBPool, serverConfigService, nil)
	rbacHandler := rbac_management.NewRBACHandler(store)
	rbac_management.RegisterAdminRBACRoutes(adminAPI, rbacHandler, jwtCfg.SecretName)

	// Initialize RBAC configurator for centralized RBAC control
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   0,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	redisSessionManager, err := session.NewSessionManager(redisClient, logr, "sess:")
	if err != nil {
		log.Fatalf("Failed to create Redis session manager: %v", err)
	}
	rbacService := store // Implements RBACService interface
	rbacConfigurator := rbac.InitializeRBAC(rbacService, redisSessionManager, serverConfigService, 30*time.Second)

	// Setup common bypass patterns (login, health checks, etc.)
	if err := rbac.SetupCommonBypassPatterns(rbacConfigurator); err != nil {
		log.Printf("Warning: Failed to setup common RBAC bypass patterns: %v", err)
	}

	// Apply RBAC middleware to protected API groups
	protectedAPI := adminAPI.Group("/", rbacConfigurator.Middleware())

	// Continue with regular route registration, but use protectedAPI for routes that should be RBAC-protected
	serverConfigHandler := server_config.NewHandler(serverConfigService, logr)
	server_config.RegisterAdminServerConfigRoutes(protectedAPI, serverConfigHandler, jwtCfg.SecretName, securityStore)

	redisSessionAdapter := session.NewRedisSessionAdapter(redisSessionManager)
	securityHandler := &security_management.SecurityHandler{
		Store:                       securityStore,
		PasswordService:             securityStore,
		SessionService:              redisSessionAdapter,
		SecurityAuditLogService:     securityStore,
		LoginHistoryService:         securityStore,
		MFAService:                  securityStore,
		PasswordResetTokenService:   securityStore,
		APIKeyService:               securityStore,
		DeviceService:               securityStore,
		BreachService:               securityStore,
		SecurityPolicyService:       securityStore,
		SecurityAnalyticsService:    securityStore,
		NotificationService:         securityStore,
		SecurityModuleConfigService: securityStore,
	}

	// Initialize auth manager with JWT as the default provider
	authManager := auth.NewAuthManager(logr)

	// Create JWT provider
	jwtConfig := jwtProvider.DefaultConfig()
	jwtConfig.Secret = jwtCfg.SecretName
	jwtConfig.Issuer = "subinc-backend"
	jwtConfig.TokenExpiry = 24 * time.Hour // 24 hour token expiry

	jwtAuthProvider, err := jwtProvider.NewJWTProvider(jwtConfig)
	if err != nil {
		log.Fatalf("Failed to create JWT provider: %v", err)
	}

	// Register JWT provider and set as default
	if err := authManager.RegisterProvider(jwtAuthProvider); err != nil {
		log.Fatalf("Failed to register JWT provider: %v", err)
	}

	if err := authManager.SetDefaultProvider("jwt"); err != nil {
		log.Fatalf("Failed to set JWT as default provider: %v", err)
	}

	// Assign auth manager to security handler
	securityHandler.Auth = authManager

	security_management.RegisterRoutes(adminAPI, securityHandler, jwtCfg.SecretName, securityStore)

	userStore := user_management.NewPostgresStore(ownerDBPool, serverConfigService, securityStore)
	userHandler := user_management.NewUserHandler(userStore)
	user_management.RegisterRoutes(protectedAPI, userHandler, jwtCfg.SecretName, securityStore)

	tenantStore := tenant_management.NewPostgresStore(ownerDBPool, serverConfigService, securityStore)
	tenantHandler := tenant_management.NewTenantHandler(tenantStore, tenantStore)
	tenant_management.RegisterRoutes(protectedAPI, tenantHandler, jwtCfg.SecretName, securityStore)

	projectStore := project_management.NewPostgresStore(ownerDBPool, serverConfigService, securityStore)
	projectHandler := project_management.NewProjectHandler(projectStore)
	project_management.RegisterRoutes(protectedAPI, projectHandler, jwtCfg.SecretName, securityStore)

	orgStore := organization_management.NewPostgresStore(ownerDBPool, serverConfigService, securityStore)
	orgHandler := organization_management.NewOrganizationHandler(orgStore)
	organization_management.RegisterRoutes(protectedAPI, orgHandler, jwtCfg.SecretName, securityStore)

	billingStore := billing_management.NewPostgresStore(ownerDBPool, serverConfigService, securityStore)
	paymentStore := &payment.PostgresStore{DB: ownerDBPool}
	billingHandler := billing_management.NewBillingHandler(billingStore, paymentStore)
	billingHandler.Notify = securityStore

	// Initialize billing plugin system
	initializeBillingPlugins(billingHandler, serverConfigService, logr)

	// Register billing-management main router
	billingRoute := protectedAPI.Group("/billing-management")
	billing_management.RegisterRoutes(protectedAPI, billingHandler, jwtCfg.SecretName, securityStore)

	// Register all billing-management submodule routers under /billing-management
	// --- FEE ---
	feeStore := fee.NewPostgresStore(ownerDBPool)
	feeHandler := &fee.FeeHandler{Store: feeStore}
	fee.RegisterRoutes(billingRoute, feeHandler)

	// --- DISCOUNT ---
	discountStore := &discount.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore, ServerConfigService: serverConfigService}
	accountStore := &account.PostgresStore{DB: ownerDBPool}
	discountHandler := discount.NewDiscountHandler(
		&discount.DiscountServiceAdapter{Store: discountStore}, // DiscountService
		&discount.CouponServiceAdapter{Store: discountStore},   // CouponService
		&discount.CreditServiceAdapter{Store: discountStore},   // CreditService
		&account.BillingAccountServiceAdapter{Store: accountStore},
		*logr,
	)
	discount.RegisterRoutes(billingRoute, discountHandler, jwtCfg.SecretName, securityStore)

	// --- PAYMENT ---
	paymentHandler := payment.NewPaymentHandler(
		&payment.PaymentServiceAdapter{Store: paymentStore},      // PaymentService
		&payment.RefundServiceAdapter{Store: paymentStore},       // RefundService
		&payment.ManualRefundServiceAdapter{Store: paymentStore}, // ManualRefundService
		billingHandler.PaymentMethodService,
		billingHandler.RateLimitService,
		serverConfigService,
		*logr,
		securityStore,
		paymentStore,
	)
	payment.RegisterRoutes(billingRoute, paymentHandler, jwtCfg.SecretName, securityStore)

	// --- TAX ---
	taxStore := &tax.PostgresStore{DB: ownerDBPool}
	taxHandler := &tax.TaxHandler{
		TaxInfoService: billingHandler.TaxService,
		Store:          *taxStore,
	}
	tax.RegisterRoutes(billingRoute, taxHandler, jwtCfg.SecretName)

	// --- ACCOUNT ---
	accountHandler := &account.AccountHandler{
		BillingAccountService: &account.BillingAccountServiceAdapter{Store: accountStore},
		NotificationService:   securityStore,
		RateLimitService:      &billingHandler.RateLimitService,
	}
	account.RegisterRoutes(billingRoute, accountHandler, jwtCfg.SecretName, billingHandler.RateLimitService)

	// --- SUBSCRIPTION ---
	subscriptionStore := &subscription.PostgresStore{DB: ownerDBPool}
	subscriptionHandler := &subscription.SubscriptionHandler{
		PlanService:         &subscription.PlanServiceAdapter{Store: subscriptionStore},
		UsageService:        &subscription.UsageServiceAdapter{Store: subscriptionStore},
		SubscriptionService: &subscription.SubscriptionServiceAdapter{Store: subscriptionStore},
		Store:               subscriptionStore,
	}
	subscription.RegisterRoutes(billingRoute, subscriptionHandler, securityStore)

	// Dunning worker setup

	if os.Getenv("DUNNING_ENABLED") == "true" {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for {
				billing_management.DunningWorker(billingStore, paymentStore, billingHandler.AccountService, billingHandler.Notify)
				<-ticker.C
			}
		}()
	}

	// if gqlCfg.Enabled {
	// 	schema, err := graphql.NewSchema(graphql.SchemaConfig{
	// 		Query:    nil,
	// 		Mutation: nil,
	// 	})
	// 	if err != nil {
	// 		log.Fatalf("Failed to create GraphQL schema: %v", err)
	// 	}
	// 	docmanagement.UnifiedGraphQLHandler(app, schema)
	// }

	userCount, err := securityStore.CountUsers(ctx)
	if err != nil {
		log.Fatalf("Failed to count users: %v", err)
	}
	if userCount == 0 {
		ownerEmail := "admin@subinc.com"
		ownerPassword := "falc0nreaper!"
		if ownerEmail == "" || ownerPassword == "" {
			log.Fatalf("OWNER_EMAIL and OWNER_PASSWORD env vars required for first owner admin bootstrap")
		}
		_, err := securityStore.RegisterUser(ctx, ownerEmail, ownerPassword)
		if err != nil {
			log.Fatalf("Failed to bootstrap owner admin: %v", err)
		}
		log.Printf("Owner admin bootstrapped: %s", ownerEmail)
	}

	// --- Serve Swagger/OpenAPI spec ---
	// To generate: swagger generate spec -o ./swagger.json --scan-models
	// @Summary      Get OpenAPI spec
	// @Description  Returns the OpenAPI (Swagger) JSON spec for the API
	// @Tags         docs
	// @Produce      json
	// @Success      200 {object} map[string]interface{}
	// @Failure      404 {string} string "swagger.json not found"
	app.Get("/swagger.json", func(c *fiber.Ctx) error {
		data, err := os.ReadFile("swagger.json")
		if err != nil {
			return c.Status(404).SendString("swagger.json not found")
		}
		c.Set("Content-Type", "application/json")
		return c.Send(data)
	})
	// Serve Swagger UI and OpenAPI YAML
	app.Static("/swagger.yaml", "./swagger.yaml")
	app.Static("/docs", "./swagger-ui", fiber.Static{Index: "index.html"})
	app.Get("/docs", func(c *fiber.Ctx) error {
		return c.Redirect("/docs/index.html", fiber.StatusFound)
	})
	logger.LogInfo("Swagger UI available at http://localhost:8080/docs, spec at /swagger.yaml")

	// Start go-swagger serve as a subprocess for Swagger UI (Swagger 2.0 only)
	cmd := exec.Command("swagger", "serve", "--flavor=swagger", "./swagger.json", "--port=8090", "--no-open")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start swagger UI: %v", err)
	}
	logger.LogInfo("Swagger UI available at http://localhost:8090/docs, spec at /swagger.json (Swagger 2.0 only)")

	if err := app.Listen(fmt.Sprintf(":%s", serverPort)); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// getDBPool returns the current DB pool (thread-safe)
func getDBPool() *pgxpool.Pool {
	dbStateMu.RLock()
	defer dbStateMu.RUnlock()
	return dbState.pool
}

// getAuditLogger returns the current audit logger (thread-safe)
func getAuditLogger() security_management.AuditLogger {
	dbStateMu.RLock()
	defer dbStateMu.RUnlock()
	return dbState.auditLogger
}

// initializeBillingPlugins loads and configures the billing plugins
func initializeBillingPlugins(handler *billing_management.BillingAdminHandler, configService *server_config.Service, logger *logger.Logger) {
	if handler == nil || handler.PluginManager == nil {
		logger.Error("Cannot initialize billing plugins: handler or plugin manager is nil")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get billing configuration from server config
	billingCfg, err := configService.GetOwnerBillingConfig(ctx)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to load billing config: %v", err))
		return
	}

	// Convert to map for plugin manager
	config := map[string]interface{}{
		"tax_rate":    billingCfg.TaxRate,
		"fixed_fee":   billingCfg.FixedFee,
		"percent_fee": billingCfg.PercentFee,
	}

	// Initialize plugins with configuration
	if err := handler.PluginManager.InitializePlugins(config); err != nil {
		logger.Error(fmt.Sprintf("Failed to initialize billing plugins: %v", err))
		return
	}

	// Log available plugins
	invoicePlugins := handler.PluginManager.ListPlugins("invoice")
	paymentPlugins := handler.PluginManager.ListPlugins("payment")
	taxPlugins := handler.PluginManager.ListPlugins("tax")

	logger.Info(fmt.Sprintf("Billing plugin system initialized with %d invoice, %d payment, and %d tax plugins",
		len(invoicePlugins), len(paymentPlugins), len(taxPlugins)))
}
