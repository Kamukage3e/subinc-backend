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

// --- Refresh Token Management ---
func (s *PostgresUserStore) CreateRefreshToken(ctx context.Context, t *RefreshToken) error {
	const q = `INSERT INTO refresh_tokens (token_id, user_id, tenant_id, token, expires_at, created_at, revoked) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.DB.Exec(ctx, q, t.TokenID, t.UserID, t.TenantID, t.Token, t.ExpiresAt, t.CreatedAt, t.Revoked)
	return err
}

func (s *PostgresUserStore) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	const q = `SELECT token_id, user_id, tenant_id, token, expires_at, created_at, revoked FROM refresh_tokens WHERE token = $1`
	row := s.DB.QueryRow(ctx, q, token)
	t := &RefreshToken{}
	if err := row.Scan(&t.TokenID, &t.UserID, &t.TenantID, &t.Token, &t.ExpiresAt, &t.CreatedAt, &t.Revoked); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *PostgresUserStore) RevokeRefreshToken(ctx context.Context, token string) error {
	const q = `UPDATE refresh_tokens SET revoked = true WHERE token = $1`
	_, err := s.DB.Exec(ctx, q, token)
	return err
}

func (s *PostgresUserStore) RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error {
	const q = `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	return err
}

// --- Password Reset Token Management ---
func (s *PostgresUserStore) CreatePasswordResetToken(ctx context.Context, t *PasswordResetToken) error {
	const q = `INSERT INTO password_reset_tokens (token, user_id, tenant_id, expires_at, used, created_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.DB.Exec(ctx, q, t.Token, t.UserID, t.TenantID, t.ExpiresAt, t.Used, t.CreatedAt)
	return err
}

func (s *PostgresUserStore) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	const q = `SELECT token, user_id, tenant_id, expires_at, used, created_at FROM password_reset_tokens WHERE token = $1`
	row := s.DB.QueryRow(ctx, q, token)
	t := &PasswordResetToken{}
	if err := row.Scan(&t.Token, &t.UserID, &t.TenantID, &t.ExpiresAt, &t.Used, &t.CreatedAt); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *PostgresUserStore) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	const q = `UPDATE password_reset_tokens SET used = true WHERE token = $1`
	_, err := s.DB.Exec(ctx, q, token)
	return err
}

// --- Email Verification Token Management ---
func (s *PostgresUserStore) CreateEmailVerificationToken(ctx context.Context, t *EmailVerificationToken) error {
	const q = `INSERT INTO email_verification_tokens (token, user_id, tenant_id, expires_at, used, created_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.DB.Exec(ctx, q, t.Token, t.UserID, t.TenantID, t.ExpiresAt, t.Used, t.CreatedAt)
	return err
}

func (s *PostgresUserStore) GetEmailVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error) {
	const q = `SELECT token, user_id, tenant_id, expires_at, used, created_at FROM email_verification_tokens WHERE token = $1`
	row := s.DB.QueryRow(ctx, q, token)
	t := &EmailVerificationToken{}
	if err := row.Scan(&t.Token, &t.UserID, &t.TenantID, &t.ExpiresAt, &t.Used, &t.CreatedAt); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *PostgresUserStore) MarkEmailVerificationTokenUsed(ctx context.Context, token string) error {
	const q = `UPDATE email_verification_tokens SET used = true WHERE token = $1`
	_, err := s.DB.Exec(ctx, q, token)
	return err
}

func (s *PostgresUserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at, email_verified FROM users WHERE email = $1`
	row := s.DB.QueryRow(ctx, q, email)
	var u User
	var roles []string
	var attributes map[string]string
	if err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt, &u.EmailVerified); err != nil {
		return nil, err
	}
	u.Roles = roles
	u.Attributes = attributes
	return &u, nil
}
