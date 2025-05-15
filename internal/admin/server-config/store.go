package server_config

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Store provides DB-backed CRUD for server config and audit history.
type Store struct {
	db  *pgxpool.Pool
	log *logger.Logger
}

func NewStore(db *pgxpool.Pool, log *logger.Logger) *Store {
	return &Store{db: db, log: log}
}

func (s *Store) Get(ctx context.Context, key string) (ServerConfig, error) {
	const q = `SELECT key, value, version, updated_at FROM server_config WHERE key = $1`
	row := s.db.QueryRow(ctx, q, key)
	var cfg ServerConfig
	if err := row.Scan(&cfg.Key, &cfg.Value, &cfg.Version, &cfg.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ServerConfig{
				Key:       key,
				Value:     "",
				Version:   1,
				UpdatedAt: time.Now().UTC(),
			}, nil
		}
		s.log.Error("server_config get failed", logger.ErrorField(err), logger.String("key", key))
		return ServerConfig{}, ErrConfigNotFound
	}
	return cfg, nil
}

func (s *Store) Set(ctx context.Context, key, value, updatedBy string) (ServerConfig, error) {
	const upsert = `INSERT INTO server_config (key, value, version, updated_at) VALUES ($1, $2, 1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, version = server_config.version + 1, updated_at = NOW()
		RETURNING key, value, version, updated_at`
	row := s.db.QueryRow(ctx, upsert, key, value)
	var cfg ServerConfig
	if err := row.Scan(&cfg.Key, &cfg.Value, &cfg.Version, &cfg.UpdatedAt); err != nil {
		s.log.Error("server_config set failed", logger.ErrorField(err), logger.String("key", key))
		return ServerConfig{}, errors.New("failed to set config")
	}
	if err := s.addHistory(ctx, cfg, updatedBy); err != nil {
		s.log.Error("server_config history failed", logger.ErrorField(err), logger.String("key", key))
	}
	return cfg, nil
}

func (s *Store) List(ctx context.Context) ([]ServerConfig, error) {
	const q = `SELECT key, value, version, updated_at FROM server_config ORDER BY key ASC`
	rows, err := s.db.Query(ctx, q)
	if err != nil {
		s.log.Error("server_config list failed", logger.ErrorField(err))
		return nil, errors.New("failed to list config")
	}
	defer rows.Close()
	var out []ServerConfig
	for rows.Next() {
		var cfg ServerConfig
		if err := rows.Scan(&cfg.Key, &cfg.Value, &cfg.Version, &cfg.UpdatedAt); err != nil {
			s.log.Error("server_config scan failed", logger.ErrorField(err))
			return nil, errors.New("failed to scan config")
		}
		out = append(out, cfg)
	}
	return out, nil
}

func (s *Store) addHistory(ctx context.Context, cfg ServerConfig, updatedBy string) error {
	const q = `INSERT INTO server_config_history (key, value, version, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.Exec(ctx, q, cfg.Key, cfg.Value, cfg.Version, cfg.UpdatedAt, updatedBy)
	if err != nil {
		s.log.Error("server_config history failed", logger.ErrorField(err), logger.String("key", cfg.Key))
	}
	return err
}

func (s *Store) History(ctx context.Context, key string) ([]ServerConfigHistory, error) {
	const q = `SELECT id, key, value, version, updated_at, updated_by FROM server_config_history WHERE key = $1 ORDER BY version DESC`
	rows, err := s.db.Query(ctx, q, key)
	if err != nil {
		s.log.Error("server_config history failed", logger.ErrorField(err), logger.String("key", key))
		return nil, errors.New("failed to get config history")
	}
	defer rows.Close()
	var out []ServerConfigHistory
	for rows.Next() {
		var h ServerConfigHistory
		if err := rows.Scan(&h.ID, &h.Key, &h.Value, &h.Version, &h.UpdatedAt, &h.UpdatedBy); err != nil {
			s.log.Error("server_config history scan failed", logger.ErrorField(err))
			return nil, errors.New("failed to scan config history")
		}
		out = append(out, h)
	}
	return out, nil
}

func (s *Store) ListMigrationStatus(ctx context.Context) ([]MigrationStatus, error) {
	rows, err := s.db.Query(ctx, `SELECT name, version, status, started_at, completed_at, error FROM migration_status`)
	if err != nil {
		s.log.Error("migration_status list failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var result []MigrationStatus
	for rows.Next() {
		var ms MigrationStatus
		var completedAt pgtype.Timestamptz
		var errStr *string
		if err := rows.Scan(&ms.Name, &ms.Version, &ms.Status, &ms.StartedAt, &completedAt, &errStr); err != nil {
			s.log.Error("migration_status scan failed", logger.ErrorField(err))
			return nil, errors.New("failed to scan migration status")
		}
		if completedAt.Valid {
			t := completedAt.Time
			ms.CompletedAt = &t
		}
		ms.Error = errStr
		result = append(result, ms)
	}
	return result, nil
}

func (s *Store) GetMigrationStatus(ctx context.Context, name string) (*MigrationStatus, error) {
	row := s.db.QueryRow(ctx, `SELECT name, version, status, started_at, completed_at, error FROM migration_status WHERE name = $1`, name)
	var ms MigrationStatus
	var completedAt pgtype.Timestamptz
	var errStr *string
	if err := row.Scan(&ms.Name, &ms.Version, &ms.Status, &ms.StartedAt, &completedAt, &errStr); err != nil {
		if err == pgx.ErrNoRows {
			s.log.Error("migration_status get failed", logger.ErrorField(err), logger.String("name", name))
			return nil, nil
		}
		return nil, errors.New("failed to get migration status")
	}
	if completedAt.Valid {
		t := completedAt.Time
		ms.CompletedAt = &t
	}
	ms.Error = errStr
	return &ms, nil
}

func (s *Store) SetMigrationStatus(ctx context.Context, status *MigrationStatus) (*MigrationStatus, error) {
	_, err := s.db.Exec(ctx, `INSERT INTO migration_status (name, version, status, started_at, completed_at, error)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (name) DO UPDATE SET version = $2, status = $3, started_at = $4, completed_at = $5, error = $6`,
		status.Name, status.Version, status.Status, status.StartedAt, status.CompletedAt, status.Error)
	if err != nil {
		s.log.Error("migration_status set failed", logger.ErrorField(err), logger.String("name", status.Name))
		return nil, errors.New("failed to set migration status")
	}
	return status, nil
}
