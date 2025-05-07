package server

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
)

// GetUnifiedDatabaseDSN returns the canonical DSN for all DB access (migrations, pool, etc).
// This is the only place in the codebase that should build or fetch the DB DSN.
// SaaS prod: guarantees all DB access uses the same config/env logic.
func GetUnifiedDatabaseDSN() (string, error) {
	dsn := viper.GetString("database.dsn")
	if dsn == "" {
		dsn = viper.GetString("database.url")
	}
	if dsn == "" {
		return "", fmt.Errorf("database DSN not set in config or env (database.dsn or database.url required)")
	}
	return dsn, nil
}

// NewPostgresPool returns a production-ready pgx pool using the unified DSN from config/env.
// This guarantees the app and migrations always use the same DB and schema.
// SaaS prod: never use POSTGRES_URL/POSTGRES_DB/etc. Only use database.dsn or database.url for all DB access.
func NewPostgresPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn, err := GetUnifiedDatabaseDSN()
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid postgres config: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}
	return pool, nil
}

// PostgresHealthCheck runs SELECT 1 and returns error if not healthy.
func PostgresHealthCheck(ctx context.Context, pool *pgxpool.Pool) error {
	row := pool.QueryRow(ctx, "SELECT 1")
	var n int
	if err := row.Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("unexpected result from postgres health check")
	}
	return nil
}
