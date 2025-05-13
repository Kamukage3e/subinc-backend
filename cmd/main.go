package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	billing_management "github.com/subinc/subinc-backend/internal/admin/billing-management"
	organization_management "github.com/subinc/subinc-backend/internal/admin/organization-management"
	project_management "github.com/subinc/subinc-backend/internal/admin/project-management"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
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
	serverConfigService := server_config.NewService(serverConfigStore, 30*time.Second, &security_management.PostgresStore{DB: ownerDBPool}, nil)

	logCfg, err := serverConfigService.GetOwnerLoggingConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load logging config: %v", err)
	}
	logr := logger.NewProduction(logger.InfoLevel, logCfg.Format, logCfg.Color, logCfg.Service, logCfg.Env)

	jwtCfg, err := serverConfigService.GetOwnerJWTSecretConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load JWT secret config: %v", err)
	}

	serverPort := os.Getenv("PORT")
	if serverPort == "" {
		serverPort = "8080"
	}

	app := fiber.New()

	// --- Owner admin routes ---
	ownerAPI := app.Group("/api/v1/owner-admin")
	store := &rbac_management.PostgresStore{DB: ownerDBPool, AuditLogger: &security_management.PostgresStore{DB: ownerDBPool}}
	rbacHandler := rbac_management.NewRBACHandler(store)
	rbac_management.RegisterAdminRBACRoutes(ownerAPI, rbacHandler, jwtCfg.SecretName)
	serverConfigHandler := server_config.NewHandler(serverConfigService, logr)
	server_config.RegisterAdminServerConfigRoutes(ownerAPI, serverConfigHandler, jwtCfg.SecretName)
	securityStore := &security_management.PostgresStore{DB: ownerDBPool}

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
	security_management.RegisterAdminSecurityRoutes(ownerAPI, securityHandler, jwtCfg.SecretName)
	userStore := &user_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
	userHandler := user_management.NewUserHandler(userStore)
	user_management.RegisterAdminUserRoutes(ownerAPI, userHandler, jwtCfg.SecretName)
	tenantStore := &tenant_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
	tenantHandler := tenant_management.NewTenantHandler(tenantStore)
	tenant_management.RegisterAdminTenantRoutes(ownerAPI, tenantHandler, jwtCfg.SecretName)
	projectStore := &project_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
	projectHandler := project_management.NewProjectHandler(projectStore)
	project_management.RegisterAdminProjectRoutes(ownerAPI, projectHandler, jwtCfg.SecretName)
	orgStore := &organization_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
	orgHandler := organization_management.NewOrganizationHandler(orgStore)
	organization_management.RegisterAdminOrganizationRoutes(ownerAPI, orgHandler, jwtCfg.SecretName)
	billingStore := &billing_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
	billingHandler := billing_management.NewBillingHandler(billingStore)
	billing_management.RegisterAdminBillingRoutes(ownerAPI, billingHandler, jwtCfg.SecretName)

	// --- Owner admin bootstrap (automatic, no endpoint) ---
	userCount, err := securityStore.CountUsers(ctx)
	if err != nil {
		log.Fatalf("Failed to count users: %v", err)
	}
	if userCount == 0 {
		ownerEmail := "admin@subinc.com"
		ownerPassword := "admin"
		if ownerEmail == "" || ownerPassword == "" {
			log.Fatalf("OWNER_EMAIL and OWNER_PASSWORD env vars required for first owner admin bootstrap")
		}
		_, err := securityStore.RegisterUser(ctx, ownerEmail, ownerPassword)
		if err != nil {
			log.Fatalf("Failed to bootstrap owner admin: %v", err)
		}
		log.Printf("Owner admin bootstrapped: %s", ownerEmail)
	}

	// --- Client admin routes ---
	// app.Use("/api/v1/client-admin", withDB)
	clientAPI := app.Group("/api/v1/client-admin")
	clientAPI.All("/*", func(c *fiber.Ctx) error {
		dbURL, err := extractDBConfig(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid DB credentials"})
		}
		dbpool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB connect failed"})
		}
		defer dbpool.Close()

		jwtSecret := c.Get("X-JWT-Secret")
		if jwtSecret == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing JWT secret"})
		}
		// User Management
		userStore := &user_management.PostgresStore{DB: dbpool, AuditLogger: securityStore}
		userHandler := user_management.NewUserHandler(userStore)
		user_management.RegisterAdminUserRoutes(clientAPI, userHandler, jwtSecret)
		// Tenant Management
		tenantStore := &tenant_management.PostgresStore{DB: dbpool, AuditLogger: securityStore}
		tenantHandler := tenant_management.NewTenantHandler(tenantStore)
		tenant_management.RegisterAdminTenantRoutes(clientAPI, tenantHandler, jwtSecret)
		// Project Management
		projectStore := &project_management.PostgresStore{DB: dbpool, AuditLogger: securityStore}
		projectHandler := project_management.NewProjectHandler(projectStore)
		project_management.RegisterAdminProjectRoutes(clientAPI, projectHandler, jwtSecret)
		// Organization Management
		orgStore := &organization_management.PostgresStore{DB: dbpool, AuditLogger: securityStore}
		orgHandler := organization_management.NewOrganizationHandler(orgStore)
		organization_management.RegisterAdminOrganizationRoutes(clientAPI, orgHandler, jwtSecret)
		// Billing Management
		billingStore := &billing_management.PostgresStore{DB: dbpool, AuditLogger: securityStore}
		billingHandler := billing_management.NewBillingHandler(billingStore)
		billing_management.RegisterAdminBillingRoutes(clientAPI, billingHandler, jwtSecret)
		return c.Next()
	})

	if err := app.Listen(fmt.Sprintf(":%s", serverPort)); err != nil {
		log.Fatalf("Fiber failed: %v", err)
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

// // Handlers for client admin config
// func getClientOAuthConfig(c *fiber.Ctx) error {
// 	// RBAC: only admin
// 	if !isClientAdmin(c) {
// 		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
// 	}
// 	return c.JSON(security_management.OAuthConfig{
// 		Google: struct {
// 			ClientID     string   `json:"client_id"`
// 			ClientSecret string   `json:"client_secret"`
// 			RedirectURI  string   `json:"redirect_uri"`
// 			Scopes       []string `json:"scopes"`
// 		}{
// 			ClientID:     "google_client_id",
// 			ClientSecret: "google_client_secret",
// 			RedirectURI:  "google_redirect_uri",
// 			Scopes:       []string{"scope1", "scope2"},
// 		},
// 	})
// }

// func setClientOAuthConfig(c *fiber.Ctx) error {
// 	if !isClientAdmin(c) {
// 		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
// 	}
// 	var cfg security_management.OAuthConfig
// 	if err := c.BodyParser(&cfg); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
// 	}
// 	return c.SendStatus(fiber.StatusNoContent)
// }

// func getClientSAMLConfig(c *fiber.Ctx) error {
// 	if !isClientAdmin(c) {
// 		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
// 	}
// 	return c.JSON(security_management.SAMLConfig{
// 		MetadataURL: "saml_metadata_url",
// 		EntityID:    "saml_entity_id",
// 		ACSURL:      "saml_acs_url",
// 	})
// }

// func setClientSAMLConfig(c *fiber.Ctx) error {
// 	if !isClientAdmin(c) {
// 		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
// 	}
// 	var cfg security_management.SAMLConfig
// 	if err := c.BodyParser(&cfg); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
// 	}
// 	return c.SendStatus(fiber.StatusNoContent)
// }

// func isClientAdmin(c *fiber.Ctx) bool {
// 	// Implement RBAC check for client admin
// 	return c.Get("X-Admin") == "true"
// }
