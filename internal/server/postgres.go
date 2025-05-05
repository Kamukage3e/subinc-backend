package server

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgresPool returns a production-ready pgx pool. Reads POSTGRES_URL or POSTGRES_HOST/PORT/USER/PASSWORD/DB from env.
func NewPostgresPool(ctx context.Context) (*pgxpool.Pool, error) {
	url := os.Getenv("POSTGRES_URL")
	if url == "" {
		host := os.Getenv("POSTGRES_HOST")
		if host == "" {
			host = "localhost"
		}
		port := os.Getenv("POSTGRES_PORT")
		if port == "" {
			port = "5432"
		}
		user := os.Getenv("POSTGRES_USER")
		if user == "" {
			user = "postgres"
		}
		pass := os.Getenv("POSTGRES_PASSWORD")
		db := os.Getenv("POSTGRES_DB")
		if db == "" {
			db = "postgres"
		}
		url = fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, pass, host, port, db)
	}
	cfg, err := pgxpool.ParseConfig(url)
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
