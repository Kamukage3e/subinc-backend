package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"syscall"

	"io/ioutil"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	billing_management "github.com/subinc/subinc-backend/internal/admin/billing-management"
	organization_management "github.com/subinc/subinc-backend/internal/admin/organization-management"
	project_management "github.com/subinc/subinc-backend/internal/admin/project-management"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
	user_management "github.com/subinc/subinc-backend/internal/admin/user-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
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

// ... implement all required methods for each module by delegating to a new PostgresStore with current dbState ...

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
func withDB(next fiber.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		dbURL, err := extractDBConfig(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid DB credentials"})
		}
		dbpool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB connect failed"})
		}
		defer dbpool.Close()
		store := &rbac_management.PostgresStore{DB: dbpool, AuditLogger: &security_management.PostgresStore{DB: dbpool}}
		c.Locals("rbacStore", store)
		return next(c)
	}
}

// Config struct for owner admin
// Add all required fields for DB, logging, etc.
type OwnerConfig struct {
	DB struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
		SSLMode  string `yaml:"sslmode"`
	} `yaml:"db"`
	Logging struct {
		Format  string `yaml:"format"`
		Color   bool   `yaml:"color"`
		Service string `yaml:"service"`
		Env     string `yaml:"env"`
	} `yaml:"logging"`
	JWTSecretName string `yaml:"jwt_secret_name"`
}

func loadOwnerConfig(path string) (*OwnerConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg OwnerConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func main() {
	configPath := os.Getenv("OWNER_CONFIG_PATH")
	var ownerCfg *OwnerConfig
	var ownerDBPool *pgxpool.Pool
	if configPath != "" {
		cfg, err := loadOwnerConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load owner config: %v", err)
		}
		ownerCfg = cfg
		dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", cfg.DB.User, cfg.DB.Password, cfg.DB.Host, cfg.DB.Port, cfg.DB.Name, cfg.DB.SSLMode)
		ownerDBPool, err = pgxpool.New(context.Background(), dbURL)
		if err != nil {
			log.Fatalf("Failed to connect to owner DB: %v", err)
		}
		_ = logger.NewProduction(logger.InfoLevel, cfg.Logging.Format, cfg.Logging.Color, cfg.Logging.Service, cfg.Logging.Env)
	}

	serverPort := os.Getenv("PORT")
	if serverPort == "" {
		serverPort = "8080"
	}

	app := fiber.New()

	// --- Owner admin routes ---
	if ownerCfg != nil && ownerDBPool != nil {
		ownerAPI := app.Group("/api/v1/owner-admin")
		// RBAC
		store := &rbac_management.PostgresStore{DB: ownerDBPool, AuditLogger: &security_management.PostgresStore{DB: ownerDBPool}}
		rbacHandler := rbac_management.NewRBACHandler(store)
		rbac_management.RegisterAdminRBACRoutes(ownerAPI, rbacHandler, ownerCfg.JWTSecretName)
		// Server Config
		serverConfigStore := server_config.NewStore(ownerDBPool, logger.NewProduction(logger.InfoLevel, ownerCfg.Logging.Format, ownerCfg.Logging.Color, ownerCfg.Logging.Service, ownerCfg.Logging.Env))
		serverConfigService := server_config.NewService(serverConfigStore, 30*time.Second, &security_management.PostgresStore{DB: ownerDBPool}, store)
		serverConfigHandler := server_config.NewHandler(serverConfigService, logger.NewProduction(logger.InfoLevel, ownerCfg.Logging.Format, ownerCfg.Logging.Color, ownerCfg.Logging.Service, ownerCfg.Logging.Env))
		server_config.RegisterAdminServerConfigRoutes(ownerAPI, serverConfigHandler, ownerCfg.JWTSecretName)
		// Security Management
		securityStore := &security_management.PostgresStore{DB: ownerDBPool}
		securityHandler := security_management.NewSecurityHandler(securityStore)
		security_management.RegisterAdminSecurityRoutes(ownerAPI, securityHandler, ownerCfg.JWTSecretName)
		// User Management
		userStore := &user_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
		userHandler := user_management.NewUserHandler(userStore)
		user_management.RegisterAdminUserRoutes(ownerAPI, userHandler, ownerCfg.JWTSecretName)
		// Tenant Management
		tenantStore := &tenant_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
		tenantHandler := tenant_management.NewTenantHandler(tenantStore)
		tenant_management.RegisterAdminTenantRoutes(ownerAPI, tenantHandler, ownerCfg.JWTSecretName)
		// Project Management
		projectStore := &project_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
		projectHandler := project_management.NewProjectHandler(projectStore)
		project_management.RegisterAdminProjectRoutes(ownerAPI, projectHandler, ownerCfg.JWTSecretName)
		// Organization Management
		orgStore := &organization_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
		orgHandler := organization_management.NewOrganizationHandler(orgStore)
		organization_management.RegisterAdminOrganizationRoutes(ownerAPI, orgHandler, ownerCfg.JWTSecretName)
		// Billing Management
		billingStore := &billing_management.PostgresStore{DB: ownerDBPool, AuditLogger: securityStore}
		billingHandler := billing_management.NewBillingHandler(billingStore)
		billing_management.RegisterAdminBillingRoutes(ownerAPI, billingHandler, ownerCfg.JWTSecretName)
	}

	// --- Client admin routes ---
	app.Use("/api/v1/client-admin", withDB)
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
		logFormat := c.Get("X-Log-Format", "json")
		logColor := c.Get("X-Log-Color", "false") == "true"
		logService := c.Get("X-Log-Service", "client")
		logEnv := c.Get("X-Log-Env", "prod")
		logr := logger.NewProduction(logger.InfoLevel, logFormat, logColor, logService, logEnv)

		securityStore := &security_management.PostgresStore{DB: dbpool}
		// RBAC
		store := &rbac_management.PostgresStore{DB: dbpool, AuditLogger: securityStore}
		rbacHandler := rbac_management.NewRBACHandler(store)
		rbac_management.RegisterAdminRBACRoutes(clientAPI, rbacHandler, jwtSecret)
		// Server Config
		serverConfigStore := server_config.NewStore(dbpool, logr)
		serverConfigService := server_config.NewService(serverConfigStore, 30*time.Second, securityStore, store)
		serverConfigHandler := server_config.NewHandler(serverConfigService, logr)
		server_config.RegisterAdminServerConfigRoutes(clientAPI, serverConfigHandler, jwtSecret)
		// Security Management
		securityHandler := security_management.NewSecurityHandler(securityStore)
		security_management.RegisterAdminSecurityRoutes(clientAPI, securityHandler, jwtSecret)
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

// Securely read password from terminal without echo
func readPassword() ([]byte, error) {
	return term.ReadPassword(int(syscall.Stdin))
}
