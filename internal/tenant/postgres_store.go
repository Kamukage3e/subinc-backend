package tenant

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresTenantStore implements TenantStore using PostgreSQL.
type PostgresTenantStore struct {
	DB *pgxpool.Pool
}

func NewPostgresTenantStore(db *pgxpool.Pool) *PostgresTenantStore {
	return &PostgresTenantStore{DB: db}
}

func (s *PostgresTenantStore) GetByID(ctx context.Context, id string) (*Tenant, error) {
	const q = `SELECT id, name, settings, created_at, updated_at FROM tenants WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	t := &Tenant{}
	if err := row.Scan(&t.ID, &t.Name, &t.Settings, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, errors.New("tenant not found")
	}
	return t, nil
}

func (s *PostgresTenantStore) GetByName(ctx context.Context, name string) (*Tenant, error) {
	const q = `SELECT id, name, settings, created_at, updated_at FROM tenants WHERE name = $1`
	row := s.DB.QueryRow(ctx, q, name)
	t := &Tenant{}
	if err := row.Scan(&t.ID, &t.Name, &t.Settings, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, errors.New("tenant not found")
	}
	return t, nil
}

func (s *PostgresTenantStore) Create(ctx context.Context, t *Tenant) error {
	const q = `INSERT INTO tenants (id, name, settings, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	now := time.Now().UTC()
	_, err := s.DB.Exec(ctx, q, t.ID, t.Name, t.Settings, now, now)
	if err != nil {
		return errors.New("failed to create tenant")
	}
	t.CreatedAt = now
	t.UpdatedAt = now
	return nil
}

func (s *PostgresTenantStore) Update(ctx context.Context, t *Tenant) error {
	const q = `UPDATE tenants SET name = $2, settings = $3, updated_at = $4 WHERE id = $1`
	now := time.Now().UTC()
	_, err := s.DB.Exec(ctx, q, t.ID, t.Name, t.Settings, now)
	if err != nil {
		return errors.New("failed to update tenant")
	}
	t.UpdatedAt = now
	return nil
}

func (s *PostgresTenantStore) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM tenants WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		return errors.New("failed to delete tenant")
	}
	return nil
}

func (s *PostgresTenantStore) ListAll(ctx context.Context) ([]*Tenant, error) {
	const q = `SELECT id, name, settings, created_at, updated_at FROM tenants`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		return nil, errors.New("failed to query tenants")
	}
	defer rows.Close()
	var tenants []*Tenant
	for rows.Next() {
		t := &Tenant{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Settings, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, errors.New("failed to scan tenant row")
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating tenant rows")
	}
	return tenants, nil
}
