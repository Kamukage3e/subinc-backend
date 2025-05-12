package commonutil

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// DBConfig holds PostgreSQL connection parameters
type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

// BuildConnectionString creates a PostgreSQL connection string from config
func BuildConnectionString(cfg DBConfig) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name, cfg.SSLMode)
}

// NewDBPool creates a new PostgreSQL connection pool
func NewDBPool(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		logger.LogError("failed to create database pool",
			logger.ErrorField(err),
			logger.String("connection_string_masked", MaskConnectionString(connStr)))
		return nil, err
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		logger.LogError("failed to ping database",
			logger.ErrorField(err),
			logger.String("connection_string_masked", MaskConnectionString(connStr)))
		pool.Close()
		return nil, err
	}

	return pool, nil
}

// MaskConnectionString masks sensitive information in connection strings for logging
func MaskConnectionString(connStr string) string {
	// This is a simple implementation - a production version might use regex
	if len(connStr) == 0 {
		return ""
	}

	// Find password portion and mask it
	// Format is typically: postgres://user:password@host:port/dbname?sslmode=...
	var result string
	inPassword := false
	passwordStart := -1
	passwordEnd := -1

	for i := 0; i < len(connStr); i++ {
		if connStr[i] == ':' && i+1 < len(connStr) && i > 0 && connStr[i-1] != '/' {
			inPassword = true
			passwordStart = i + 1
			continue
		}

		if inPassword && connStr[i] == '@' {
			inPassword = false
			passwordEnd = i

			// Replace password with [MASKED]
			result = connStr[:passwordStart] + "[MASKED]" + connStr[passwordEnd:]
			return result
		}
	}

	// If we couldn't parse properly, mask more aggressively
	return "postgres://[MASKED]"
}

// ValidateDBConfig validates database configuration
func ValidateDBConfig(cfg DBConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("database host required")
	}
	if cfg.Port == "" {
		return fmt.Errorf("database port required")
	}
	if cfg.User == "" {
		return fmt.Errorf("database user required")
	}
	if cfg.Password == "" {
		return fmt.Errorf("database password required")
	}
	if cfg.Name == "" {
		return fmt.Errorf("database name required")
	}
	if cfg.SSLMode == "" {
		return fmt.Errorf("database sslmode required")
	}
	return nil
}
