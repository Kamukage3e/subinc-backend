package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/migrate"
)

func main() {
	// Parse command-line arguments
	var (
		action        string
		schemaPath    string
		migrationsDir string
		dryRun        bool
		timeout       int
		baselineVer   string
	)

	flag.StringVar(&action, "action", "apply", "Migration action: apply, status, init, rollback")
	flag.StringVar(&schemaPath, "schema", "schema.hcl", "Path to schema.hcl file")
	flag.StringVar(&migrationsDir, "migrations-dir", "./migrations", "Directory for migrations")
	flag.BoolVar(&dryRun, "dry-run", false, "Dry run mode (no actual changes)")
	flag.IntVar(&timeout, "timeout", 60, "Timeout in seconds")
	flag.StringVar(&baselineVer, "baseline", "", "Baseline version for migration")
	flag.Parse()

	// Initialize logger
	logr := logger.NewProduction(logger.InfoLevel, "json", false, "migration", "prod")
	logr.Info(fmt.Sprintf("Starting migration tool with action: %s", action))

	// Load configuration
	cfg, err := config.LoadConfig(logr)
	if err != nil {
		logr.Fatal("Failed to load configuration", logger.ErrorField(err))
	}

	// Create DB URL from config
	dbURL := cfg.Database.GetDatabaseDSN()

	// Set up migration manager
	migrationCfg := migrate.MigrationConfig{
		SchemaPaths:     []string{schemaPath},
		MigrationsDir:   migrationsDir,
		URL:             dbURL,
		DryRun:          dryRun,
		Timeout:         time.Duration(timeout) * time.Second,
		BaselineVersion: baselineVer,
	}

	migrationManager := migrate.NewManager(migrationCfg, logr)
	ctx := context.Background()

	// Execute the requested action
	switch action {
	case "init":
		if err := migrationManager.Init(ctx); err != nil {
			logr.Fatal("Failed to initialize migrations", logger.ErrorField(err))
		}
		logr.Info("Migrations initialized successfully")

	case "apply":
		if err := migrationManager.Apply(ctx); err != nil {
			logr.Fatal("Failed to apply migrations", logger.ErrorField(err))
		}
		logr.Info("Migrations applied successfully")

	case "status":
		status, err := migrationManager.Status(ctx)
		if err != nil {
			logr.Fatal("Failed to get migration status", logger.ErrorField(err))
		}
		fmt.Println(status)

	case "rollback":
		if err := migrationManager.Rollback(ctx); err != nil {
			logr.Fatal("Failed to rollback migration", logger.ErrorField(err))
		}
		logr.Info("Migration rolled back successfully")

	default:
		logr.Fatal(fmt.Sprintf("Unknown action: %s. Supported actions: init, apply, status, rollback", action))
	}

	// Flush logs before exiting
	if err := logr.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to flush logs: %v\n", err)
	}
}
