package user

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresUserStore implements UserStore using PostgreSQL.
type PostgresUserStore struct {
	DB *pgxpool.Pool
}

func NewPostgresUserStore(db *pgxpool.Pool) *PostgresUserStore {
	return &PostgresUserStore{DB: db}
}

func (s *PostgresUserStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at FROM users WHERE username = $1`
	row := s.DB.QueryRow(ctx, q, username)
	u := &User{}
	var roles []string
	var attributes map[string]string
	if err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, errors.New("user not found")
	}
	u.Roles = roles
	u.Attributes = attributes
	return u, nil
}

func (s *PostgresUserStore) GetByID(ctx context.Context, id string) (*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at FROM users WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	u := &User{}
	var roles []string
	var attributes map[string]string
	if err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, errors.New("user not found")
	}
	u.Roles = roles
	u.Attributes = attributes
	return u, nil
}

func (s *PostgresUserStore) Create(ctx context.Context, u *User) error {
	const q = `INSERT INTO users (id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	now := time.Now().UTC()
	_, err := s.DB.Exec(ctx, q, u.ID, u.TenantID, u.Username, u.Email, u.PasswordHash, u.Roles, u.Attributes, now, now)
	if err != nil {
		return errors.New("failed to create user")
	}
	u.CreatedAt = now
	u.UpdatedAt = now
	return nil
}

func (s *PostgresUserStore) Update(ctx context.Context, u *User) error {
	const q = `UPDATE users SET tenant_id = $2, username = $3, email = $4, password_hash = $5, roles = $6, attributes = $7, updated_at = $8 WHERE id = $1`
	now := time.Now().UTC()
	_, err := s.DB.Exec(ctx, q, u.ID, u.TenantID, u.Username, u.Email, u.PasswordHash, u.Roles, u.Attributes, now)
	if err != nil {
		return errors.New("failed to update user")
	}
	u.UpdatedAt = now
	return nil
}

func (s *PostgresUserStore) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM users WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		return errors.New("failed to delete user")
	}
	return nil
}

func (s *PostgresUserStore) ListByTenantID(ctx context.Context, tenantID string) ([]*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at FROM users WHERE tenant_id = $1`
	rows, err := s.DB.Query(ctx, q, tenantID)
	if err != nil {
		return nil, errors.New("failed to query users by tenant")
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u := &User{}
		var roles []string
		var attributes map[string]string
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, errors.New("failed to scan user row")
		}
		u.Roles = roles
		u.Attributes = attributes
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating user rows")
	}
	return users, nil
}
