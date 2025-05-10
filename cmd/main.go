package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"


	"strings"

	"time"

	"database/sql"


	"github.com/gofiber/fiber/v2/middleware/adaptor"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/spf13/viper"



	. "github.com/subinc/subinc-backend/internal/pkg/logger"

	"github.com/subinc/subinc-backend/pkg/jobs"
	"github.com/subinc/subinc-backend/pkg/session"
)

// ErrServerClosed is returned on server graceful close
var ErrServerClosed = errors.New("server closed")

// Initialize logger
var log *Logger




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

	// Initialize secrets manager only if enabled (prod)
	useAWSSecrets := viper.GetBool("aws.secrets_manager_enabled")
	var secretsManager secrets.SecretsManager
	if useAWSSecrets {
		var err error
		secretsManager, err = secrets.NewAWSSecretsManager(ctx, log)
		if err != nil {
			log.Fatal("failed to initialize secrets manager", ErrorField(err))
		}
		log.Info("AWS Secrets Manager enabled for secrets")
	} else {
		secretsManager = secrets.NewInMemorySecretsManager()
		log.Warn("AWS Secrets Manager disabled, using in-memory secrets manager (dev/test only)")
	}
	jwtSecretName := viper.GetString("jwt.secret_name")
	if jwtSecretName == "" {
		jwtSecretName = "subinc-jwt-secret"
	}
	if !useAWSSecrets {
		if _, err := secretsManager.GetSecret(ctx, jwtSecretName); err != nil {
			secret := generateSecurePassword(64)
			if setter, ok := secretsManager.(interface{ SetSecret(string, string) }); ok {
				setter.SetSecret(jwtSecretName, secret)
			}
		}
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
