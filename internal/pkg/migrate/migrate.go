package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// MigrationConfig holds migration configuration
type MigrationConfig struct {
	SchemaPaths     []string
	MigrationsDir   string
	URL             string
	DryRun          bool
	Timeout         time.Duration
	VersionTable    string
	BaselineVersion string
}

// Manager is responsible for database migrations
type Manager struct {
	config MigrationConfig
	logger *logger.Logger
}

// NewManager creates a new migration manager
func NewManager(config MigrationConfig, logger *logger.Logger) *Manager {
	if config.Timeout == 0 {
		config.Timeout = 1 * time.Minute
	}
	if config.VersionTable == "" {
		config.VersionTable = "migration_status"
	}

	return &Manager{
		config: config,
		logger: logger,
	}
}

// Apply applies pending migrations
func (m *Manager) Apply(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()

	if m.config.URL == "" {
		return errors.New("database URL is required")
	}

	if len(m.config.SchemaPaths) == 0 {
		return errors.New("schema paths are required")
	}

	if m.config.MigrationsDir == "" {
		m.config.MigrationsDir = "./migrations"
	}

	// Create migrations directory if it doesn't exist
	if err := os.MkdirAll(m.config.MigrationsDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create migrations directory: %w", err)
	}

	// Generate migrations from schema.hcl
	if err := m.generateMigrations(ctx); err != nil {
		return fmt.Errorf("failed to generate migrations: %w", err)
	}

	// Apply migrations
	if err := m.applyMigrations(ctx); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}

// generateMigrations generates migrations from schema.hcl files
func (m *Manager) generateMigrations(ctx context.Context) error {
	m.logger.Info("Generating migrations from schema files")

	// Build the schema paths argument
	schemaArgs := []string{}
	for _, path := range m.config.SchemaPaths {
		schemaArgs = append(schemaArgs, "--schema", path)
	}

	// Build the atlas migrate diff command
	args := []string{
		"migrate", "diff",
		"--dir", fmt.Sprintf("file://%s", m.config.MigrationsDir),
		"--dev-url", m.config.URL,
		"--format", "golang-migrate",
		"--log", "info",
	}

	// Add the schema paths
	args = append(args, schemaArgs...)

	// Add migration name with timestamp
	migrationName := fmt.Sprintf("migration_%s", time.Now().Format("20060102150405"))
	args = append(args, migrationName)

	// Execute the atlas command
	cmd := exec.CommandContext(ctx, "atlas", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	m.logger.Info(fmt.Sprintf("Running command: atlas %v", args))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run atlas migrate diff: %w", err)
	}

	return nil
}

// applyMigrations applies pending migrations
func (m *Manager) applyMigrations(ctx context.Context) error {
	if m.config.DryRun {
		m.logger.Info("Dry run mode, skipping migration apply")
		return nil
	}

	m.logger.Info("Applying migrations")

	// Build the atlas migrate apply command
	args := []string{
		"migrate", "apply",
		"--dir", fmt.Sprintf("file://%s", m.config.MigrationsDir),
		"--url", m.config.URL,
		"--log", "info",
	}

	// Add baseline version if specified
	if m.config.BaselineVersion != "" {
		args = append(args, "--baseline", m.config.BaselineVersion)
	}

	// Execute the atlas command
	cmd := exec.CommandContext(ctx, "atlas", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	m.logger.Info(fmt.Sprintf("Running command: atlas %v", args))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run atlas migrate apply: %w", err)
	}

	return nil
}

// Status returns the current migration status
func (m *Manager) Status(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()

	if m.config.URL == "" {
		return "", errors.New("database URL is required")
	}

	// Build the atlas migrate status command
	args := []string{
		"migrate", "status",
		"--dir", fmt.Sprintf("file://%s", m.config.MigrationsDir),
		"--url", m.config.URL,
		"--log", "info",
	}

	// Execute the atlas command
	cmd := exec.CommandContext(ctx, "atlas", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run atlas migrate status: %w", err)
	}

	return string(output), nil
}

// Init initializes the migration structure
func (m *Manager) Init(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()

	// Create migrations directory if it doesn't exist
	if err := os.MkdirAll(m.config.MigrationsDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create migrations directory: %w", err)
	}

	// Create an atlas.hcl config file if it doesn't exist
	atlasConfigPath := filepath.Join(m.config.MigrationsDir, "atlas.hcl")
	if _, err := os.Stat(atlasConfigPath); os.IsNotExist(err) {
		content := fmt.Sprintf(`env {
  name = schema

  migration {
    dir = "file://%s"
    format = golang-migrate
    table = "%s"
  }

  url = "%s"
}`, m.config.MigrationsDir, m.config.VersionTable, m.config.URL)

		if err := os.WriteFile(atlasConfigPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to create atlas config file: %w", err)
		}
	}

	m.logger.Info("Migration structure initialized")
	return nil
}

// Rollback rolls back the last applied migration
func (m *Manager) Rollback(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()

	if m.config.URL == "" {
		return errors.New("database URL is required")
	}

	m.logger.Info("Rolling back the last migration")

	// Build the atlas migrate down command
	args := []string{
		"migrate", "down",
		"--dir", fmt.Sprintf("file://%s", m.config.MigrationsDir),
		"--url", m.config.URL,
		"--log", "info",
	}

	// Execute the atlas command
	cmd := exec.CommandContext(ctx, "atlas", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	m.logger.Info(fmt.Sprintf("Running command: atlas %v", args))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run atlas migrate down: %w", err)
	}

	return nil
}
