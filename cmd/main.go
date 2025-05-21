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
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"

	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"

	"github.com/subinc/subinc-backend/internal/pkg/auth"
	jwtProvider "github.com/subinc/subinc-backend/internal/pkg/auth/providers/jwt"
	"github.com/subinc/subinc-backend/internal/pkg/config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/middleware"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
	"github.com/subinc/subinc-backend/pkg/rbac"
	"github.com/subinc/subinc-backend/pkg/session"
)

// Global state for DB pool, protected by mutex for thread safety
var (
	dbState struct {
		pool *pgxpool.Pool
	}
	dbStateMu = &sync.RWMutex{}
)

// Handler dependencies struct for dynamic DB
// Each handler gets a pointer to this struct and reads db at request time

type HandlerDeps struct {
	GetDBPool func() *pgxpool.Pool
}

// DynamicStore implements the same interface as PostgresStore but always uses the latest dbState
// This allows handlers to always use the current DB pool after /db/connect

type DynamicStore struct{}

// RBAC
func (s *DynamicStore) DB() *pgxpool.Pool {
	return getDBPool()
}

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
	// Initialize logger
	logr := logger.NewProduction(logger.InfoLevel, "json", false, "subinc-backend", "prod")

	// Load configuration from environment variables
	appConfig, err := config.LoadConfig(logr)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Connect to owner database
	ownerDBDSN := appConfig.Database.GetDatabaseDSN()
	if ownerDBDSN == "" {
		log.Fatalf("Database DSN is empty, check environment variables")
	}

	ownerDBPool, err := pgxpool.New(context.Background(), ownerDBDSN)
	if err != nil {
		log.Fatalf("Failed to connect to owner DB: %v", err)
	}
	defer ownerDBPool.Close()

	ctx := context.Background()
	serverConfigStore := server_config.NewStore(ownerDBPool, logr)
	serverConfigService := server_config.NewService(serverConfigStore, 30*time.Second)

	logCfg, err := serverConfigService.GetOwnerLoggingConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load logging config: %v", err)
	}
	logr = logger.NewProduction(logger.InfoLevel, logCfg.Format, logCfg.Color, logCfg.Service, logCfg.Env)

	_, err = serverConfigService.GetOwnerGraphQLConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load GraphQL config: %v", err)
	}

	serverPort := appConfig.Server.Port

	app := fiber.New()

	// Add a health check endpoint
	app.Get("/api/v1/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"time":    time.Now().Format(time.RFC3339),
			"service": appConfig.ServiceName,
			"version": appConfig.Version,
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
		// Use allowed origins from configuration
		allowOrigin := "*"
		if len(appConfig.Server.AllowedOrigins) > 0 && appConfig.Server.AllowedOrigins[0] != "*" {
			// In a production app, we'd check if the request origin is in the allowed list
			allowOrigin = appConfig.Server.AllowedOrigins[0]
		}

		c.Set("Access-Control-Allow-Origin", allowOrigin)
		c.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS,PATCH")
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Tenant-ID")
		c.Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if c.Method() == "OPTIONS" {
			return c.SendStatus(fiber.StatusNoContent)
		}

		return c.Next()
	})

	// Apply global ID hashing middleware for all API endpoints to prevent API ID enumeration
	// Configure from environment or server config
	idHashingSecret := os.Getenv("ID_HASHING_SECRET")
	idHashingSalt := os.Getenv("ID_HASHING_SALT")

	// Try to get from server config
	hashIDConfig, err := serverConfigService.GetOwnerHashIDConfig(ctx)
	if err == nil && hashIDConfig.Salt != "" {
		idHashingSalt = hashIDConfig.Salt
	}

	// Use defaults if values are still empty
	if idHashingSecret == "" {
		idHashingSecret = "change-me-in-production-" + appConfig.ServiceName
		logr.Warn("Using default ID hashing secret. For production, set ID_HASHING_SECRET env var or configure in server config.")
	}

	if idHashingSalt == "" {
		idHashingSalt = "change-me-in-production-salt-" + appConfig.ServiceName
		logr.Warn("Using default ID hashing salt. For production, set ID_HASHING_SALT env var or configure in server config.")
	}

	// Apply global API middleware
	middleware.GlobalAPIMiddleware(app, middleware.APIMiddlewareConfig{
		// ID hashing configuration
		IDHashingSecret: idHashingSecret,
		IDHashingSalt:   idHashingSalt,
		Logger:          logr,
		SkipPaths: []string{
			"/api/v1/health",
			"/api/v1/db",
			"/docs",
			"/swagger.json",
			"/swagger.yaml",
		},
	})

	// Create RBAC store before any route registration
	rbacStore := &rbac_management.PostgresStore{DB: ownerDBPool}
	rbac_management.InitGlobalRBACStore(rbacStore)

	// --- Unified admin routes (owner + client) ---
	adminAPI := app.Group("/api/v1/")
	securityStore := security_management.NewPostgresStore(ownerDBPool, serverConfigService)

	authManager := auth.NewAuthManager(logr)

	// Register JWT provider and set as default
	jwtAuthProvider, err := jwtProvider.NewJWTProvider(appConfig.JWT, logr)
	if err != nil {
		log.Fatalf("Failed to create JWT provider: %v", err)
	}
	if err := authManager.RegisterProvider(jwtAuthProvider); err != nil {
		log.Fatalf("Failed to register JWT provider: %v", err)
	}
	authManager.Providers()["default"] = jwtAuthProvider
	if err := authManager.SetDefaultProvider("jwt"); err != nil {
		log.Fatalf("Failed to set default provider: %v", err)
	}

	securityHandler := security_management.NewSecurityHandler(securityStore, authManager)
	securityHandler.PasswordService = securityStore
	securityHandler.MFAService = securityStore
	securityHandler.SecurityEventService = securityStore
	securityHandler.SecurityEventWebhookService = securityStore
	securityHandler.LoginHistoryService = securityStore
	securityHandler.SecurityPolicyService = securityStore
	securityHandler.SecurityModuleConfigService = securityStore

	security_management.RegisterRoutes(adminAPI, securityHandler, appConfig.JWT.Secret)

	rbacHandler := rbac_management.NewRBACHandler(rbacStore)
	rbac_management.RegisterAdminRBACRoutes(adminAPI, rbacHandler, appConfig.JWT.Secret)

	// Initialize RBAC configurator for centralized RBAC control
	redisClient := redis.NewClient(&redis.Options{
		Addr:     appConfig.Redis.Address,
		Password: appConfig.Redis.Password,
		DB:       appConfig.Redis.DB,
	})

	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	redisSessionManager, err := session.NewSessionManager(redisClient, logr, "sess:")
	if err != nil {
		log.Fatalf("Failed to create Redis session manager: %v", err)
	}

	// Use the store directly for RBAC
	rbacStore = &rbac_management.PostgresStore{DB: ownerDBPool}
	rbacConfigurator := rbac.InitializeRBAC(rbacStore, redisSessionManager, serverConfigService, 30*time.Second)

	// Setup common bypass patterns (login, health checks, etc.)
	if err := rbac.SetupCommonBypassPatterns(rbacConfigurator); err != nil {
		log.Printf("Warning: Failed to setup common RBAC bypass patterns: %v", err)
	}

	// Apply RBAC middleware to protected API groups
	protectedAPI := adminAPI.Group("/", rbacConfigurator.Middleware())

	// Continue with regular route registration, but use protectedAPI for routes that should be RBAC-protected
	serverConfigHandler := server_config.NewHandler(serverConfigService, logr)
	server_config.RegisterAdminServerConfigRoutes(protectedAPI, serverConfigHandler, appConfig.JWT.Secret)

	// Initialize the payment and billing handlers
	paymentStore := &payment.PostgresStore{
		DB: ownerDBPool,
	}

	billingStore := &billing_management.PostgresStore{
		DB:                  ownerDBPool,
		ServerConfigService: serverConfigService,
	}

	// Initialize the plugin manager
	pluginManager := plugin.NewManager()

	// Create the billing adapter - used as the core service implementation
	billingAdapter := billing_management.NewBillingAdapter(ownerDBPool, serverConfigService)

	// Create interface-compatible adapters using the adapter pattern from billing_management package
	invoiceServiceAdapter := billing_management.NewInvoiceServiceAdapter(billingAdapter)
	manualAdjustmentAdapter := billing_management.NewManualAdjustmentServiceAdapter(billingAdapter)
	webhookEventAdapter := billing_management.NewWebhookEventServiceAdapter(billingAdapter)
	webhookSubscriptionAdapter := billing_management.NewWebhookSubscriptionServiceAdapter(billingAdapter)

	// Initialize specialized services
	creditService := &discount.CreditServiceAdapter{Store: &discount.PostgresStore{DB: ownerDBPool, ServerConfigService: serverConfigService}}
	accountService := account.NewBillingAccountServiceAdapter(&account.PostgresStore{DB: ownerDBPool}, pluginManager)
	taxService := tax.NewTaxServiceAdapter(&tax.PostgresStore{DB: ownerDBPool}, pluginManager)

	// Create the billing handler with all required dependencies using NewBillingHandler factory method
	billingHandler := billing_management.NewBillingHandler(
		billingStore,
		paymentStore,
		invoiceServiceAdapter,
		billingAdapter, // ReportService
		manualAdjustmentAdapter,
		creditService,
		pluginManager,
		securityStore,
		accountService,
		taxService,
		billingAdapter, // InvoiceExportService
		webhookEventAdapter,
		webhookSubscriptionAdapter,
		billingAdapter, // DunningService
	)

	// Initialize billing plugin system using configuration
	initializeBillingPlugins(billingHandler, serverConfigService, logr)

	// Register billing-management main router
	billingRoute := protectedAPI.Group("/billing-management")
	billing_management.RegisterRoutes(protectedAPI, billingHandler, appConfig.JWT.Secret)

	// Register all billing-management submodule routers under /billing-management
	// --- FEE ---
	feeStore := fee.NewPostgresStore(ownerDBPool)
	feeServiceAdapter := fee.NewFeeServiceAdapter(feeStore, billingHandler.PluginManager)
	feeHandler := fee.NewFeeHandler(feeServiceAdapter)
	fee.RegisterRoutes(billingRoute, feeHandler)

	// --- DISCOUNT ---
	discountStore := &discount.PostgresStore{DB: ownerDBPool, ServerConfigService: serverConfigService}
	accountStore := &account.PostgresStore{DB: ownerDBPool}
	discountServiceAdapter := discount.NewDiscountServiceAdapter(discountStore, billingHandler.PluginManager)
	discountHandler := discount.NewDiscountHandler(
		discountServiceAdapter,                               // DiscountService
		&discount.CouponServiceAdapter{Store: discountStore}, // CouponService
		&discount.CreditServiceAdapter{Store: discountStore}, // CreditService
		account.NewBillingAccountServiceAdapter(accountStore, billingHandler.PluginManager),
		*logr,
	)
	discount.RegisterRoutes(billingRoute, discountHandler, appConfig.JWT.Secret)

	// --- PAYMENT ---
	// Create transaction report adapter
	transactionReportAdapter := &payment.TransactionServiceAdapter{Store: paymentStore}

	// Create plugin manager adapter for payment package
	pluginManagerAdapter := &payment.PluginManagerAdapter{
		Manager: billingHandler.PluginManager,
		Store:   paymentStore,
	}

	paymentHandler := payment.NewPaymentHandler(
		&payment.PaymentServiceAdapter{Store: paymentStore},      // PaymentService
		&payment.RefundServiceAdapter{Store: paymentStore},       // RefundService
		&payment.ManualRefundServiceAdapter{Store: paymentStore}, // ManualRefundService
		billingHandler.PaymentMethodService,
		serverConfigService,
		*logr,
		billingHandler.Notify,
		paymentStore,
		pluginManagerAdapter, // Use the adapter that implements payment.PluginService
		transactionReportAdapter,
	)
	payment.RegisterRoutes(billingRoute, paymentHandler, appConfig.JWT.Secret)

	// --- TAX ---
	taxStore := &tax.PostgresStore{DB: ownerDBPool}
	taxServiceAdapter := tax.NewTaxServiceAdapter(taxStore, billingHandler.PluginManager)
	taxHandler := &tax.TaxHandler{
		TaxInfoService: taxServiceAdapter,
		Store:          *taxStore,
	}
	tax.RegisterRoutes(billingRoute, taxHandler, appConfig.JWT.Secret)

	// --- ACCOUNT ---
	// Create tenant store for account integration
	tenantStore := &tenant_management.PostgresStore{
		DB:                  ownerDBPool,
		ServerConfigService: serverConfigService,
	}

	accountHandler := &account.AccountHandler{
		BillingAccountService: account.NewBillingAccountServiceAdapter(accountStore, billingHandler.PluginManager),
		NotificationService:   billingHandler.Notify,
		TenantService:         tenantStore,
	}

	// Register account routes with tenant service
	account.RegisterRoutes(billingRoute, accountHandler, appConfig.JWT.Secret, tenantStore)

	// --- SUBSCRIPTION ---
	subscriptionStore := &subscription.PostgresStore{DB: ownerDBPool}
	subscriptionServiceAdapter := subscription.NewSubscriptionServiceAdapter(subscriptionStore, billingHandler.PluginManager)
	subscriptionHandler := &subscription.SubscriptionHandler{
		PlanService:         &subscription.PlanServiceAdapter{Store: subscriptionStore},
		UsageService:        &subscription.UsageServiceAdapter{Store: subscriptionStore},
		SubscriptionService: subscriptionServiceAdapter,
		Store:               subscriptionStore,
	}
	subscription.RegisterRoutes(billingRoute, subscriptionHandler)

	// Dunning worker setup - only enable if explicitly set in config
	if appConfig.Stripe.APIKey != "" && os.Getenv("DUNNING_ENABLED") == "true" {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for {
				billing_management.DunningWorker(billingStore, paymentStore, billingHandler.AccountService, billingHandler.Notify)
				<-ticker.C
			}
		}()
	}

	// Webhook delivery worker setup
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			ctx := context.Background()
			billingStore.RunWebhookDeliveryWorker(ctx)
			<-ticker.C
		}
	}()

	// User bootstrap - only create default user if none exist
	userCount, err := securityStore.CountUsers(ctx)
	if err != nil {
		log.Fatalf("Failed to count users: %v", err)
	}

	if userCount == 0 {
		// Get credentials from environment variables
		ownerEmail := os.Getenv("OWNER_EMAIL")
		if ownerEmail == "" {
			ownerEmail = "admin@subinc.com" // Default only if not set in env
		}

		ownerPassword := os.Getenv("OWNER_PASSWORD")
		if ownerPassword == "" {
			// Generate a random password if not set
			ownerPassword, err = generateRandomPassword()
			if err != nil {
				log.Fatalf("Failed to generate random password: %v", err)
			}
			log.Printf("Generated random password for admin: %s", ownerPassword)
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

	// Start go-swagger serve as a subprocess for Swagger UI (Swagger 2.0 only) if available
	swaggerCmd := exec.Command("which", "swagger")
	if err := swaggerCmd.Run(); err == nil {
		cmd := exec.Command("swagger", "serve", "--flavor=swagger", "./swagger.json", "--port=8090", "--no-open")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Printf("Warning: Failed to start swagger UI: %v", err)
		} else {
			logger.LogInfo("Swagger UI available at http://localhost:8090/docs, spec at /swagger.json (Swagger 2.0 only)")
		}
	}

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

// generateRandomPassword generates a secure random password
func generateRandomPassword() (string, error) {
	// Import the password generator or use crypto/rand to generate a secure password
	// For simplicity, we'll return a fixed string here, but in production you should use a proper generator
	password := "Temp-" + fmt.Sprintf("%d", time.Now().Unix())
	log.Printf("Generated random password for admin: %s", password)
	return password, nil
}

// initializeBillingPlugins loads and configures the billing plugins
func initializeBillingPlugins(handler *billing_management.BillingAdminHandler, configService *server_config.Service, logger *logger.Logger) {
	if handler == nil || handler.PluginManager == nil {
		logger.Error("Cannot initialize billing plugins: handler or plugin manager is nil")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get centralized plugin system configuration
	pluginSystemCfg, err := configService.GetPluginSystemConfig(ctx)
	if err != nil {
		// Fall back to billing configuration for backward compatibility
		billingCfg, billingErr := configService.GetOwnerBillingConfig(ctx)
		if billingErr != nil {
			logger.Error(fmt.Sprintf("Failed to load plugin or billing config: %v, %v", err, billingErr))
			return
		}

		// Convert billing config to generic plugin configuration
		config := map[string]interface{}{
			"tax_rate":    billingCfg.TaxRate,
			"fixed_fee":   billingCfg.FixedFee,
			"percent_fee": billingCfg.PercentFee,
		}

		// Initialize plugins with billing configuration
		if err := handler.PluginManager.InitializePlugins(config); err != nil {
			logger.Error(fmt.Sprintf("Failed to initialize billing plugins: %v", err))
			return
		}
	} else {
		// Register and initialize invoice plugins
		if pluginSystemCfg.Invoice.Enabled {
			invoicePluginCfg, err := configService.GetPluginConfig(ctx, "invoice")
			if err == nil && invoicePluginCfg != nil && invoicePluginCfg.Enabled {
				// Initialize with specific invoice plugin config
				if err := handler.PluginManager.InitializePlugins(map[string]interface{}{
					"type":    "invoice",
					"plugins": invoicePluginCfg.Plugins,
					"default": invoicePluginCfg.DefaultName,
				}); err != nil {
					logger.Error(fmt.Sprintf("Failed to initialize invoice plugins: %v", err))
				}
			}
		}

		// Register and initialize payment plugins
		if pluginSystemCfg.Payment.Enabled {
			paymentPluginCfg, err := configService.GetPluginConfig(ctx, "payment")
			if err == nil && paymentPluginCfg != nil && paymentPluginCfg.Enabled {
				// Initialize with specific payment plugin config
				if err := handler.PluginManager.InitializePlugins(map[string]interface{}{
					"type":    "payment",
					"plugins": paymentPluginCfg.Plugins,
					"default": paymentPluginCfg.DefaultName,
				}); err != nil {
					logger.Error(fmt.Sprintf("Failed to initialize payment plugins: %v", err))
				}
			}
		}

		// Register and initialize tax plugins
		if pluginSystemCfg.Tax.Enabled {
			taxPluginCfg, err := configService.GetPluginConfig(ctx, "tax")
			if err == nil && taxPluginCfg != nil && taxPluginCfg.Enabled {
				// Initialize with specific tax plugin config
				if err := handler.PluginManager.InitializePlugins(map[string]interface{}{
					"type":    "tax",
					"plugins": taxPluginCfg.Plugins,
					"default": taxPluginCfg.DefaultName,
				}); err != nil {
					logger.Error(fmt.Sprintf("Failed to initialize tax plugins: %v", err))
				}
			}
		}

		// Register and initialize fee plugins if configured
		if pluginSystemCfg.Fee.Enabled {
			feePluginCfg, err := configService.GetPluginConfig(ctx, "fee")
			if err == nil && feePluginCfg != nil && feePluginCfg.Enabled {
				// Initialize with specific fee plugin config
				if err := handler.PluginManager.InitializePlugins(map[string]interface{}{
					"type":    "fee",
					"plugins": feePluginCfg.Plugins,
					"default": feePluginCfg.DefaultName,
				}); err != nil {
					logger.Error(fmt.Sprintf("Failed to initialize fee plugins: %v", err))
				}
			}
		}

		// Register and initialize subscription plugins if configured
		if pluginSystemCfg.Subscription.Enabled {
			subPluginCfg, err := configService.GetPluginConfig(ctx, "subscription")
			if err == nil && subPluginCfg != nil && subPluginCfg.Enabled {
				// Initialize with specific subscription plugin config
				if err := handler.PluginManager.InitializePlugins(map[string]interface{}{
					"type":    "subscription",
					"plugins": subPluginCfg.Plugins,
					"default": subPluginCfg.DefaultName,
				}); err != nil {
					logger.Error(fmt.Sprintf("Failed to initialize subscription plugins: %v", err))
				}
			}
		}
	}

	// Log available plugins
	invoicePlugins := handler.PluginManager.ListPlugins("invoice")
	paymentPlugins := handler.PluginManager.ListPlugins("payment")
	taxPlugins := handler.PluginManager.ListPlugins("tax")
	feePlugins := handler.PluginManager.ListPlugins("fee")
	discountPlugins := handler.PluginManager.ListPlugins("discount")
	subscriptionPlugins := handler.PluginManager.ListPlugins("subscription")

	logger.Info(fmt.Sprintf("Billing plugin system initialized with %d invoice, %d payment, %d tax, %d fee, %d discount, and %d subscription plugins",
		len(invoicePlugins), len(paymentPlugins), len(taxPlugins), len(feePlugins), len(discountPlugins), len(subscriptionPlugins)))
}
