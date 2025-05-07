package user

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgresUserStore returns a new PostgresUserStore with a connection pool.
func NewPostgresUserStore(db *pgxpool.Pool) *PostgresUserStore {
	return &PostgresUserStore{DB: db}
}

// GetByUsername fetches a user by username. Returns user or error if not found.
func (s *PostgresUserStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at, mfa_secret, mfa_enabled, backup_codes FROM users WHERE username = $1`
	row := s.DB.QueryRow(ctx, q, username)
	u := &User{}
	var roles []string
	var attributes map[string]string
	if err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt, &u.MFASecret, &u.MFAEnabled, &u.BackupCodes); err != nil {
		return nil, errors.New("user not found")
	}
	u.Roles = roles
	u.Attributes = attributes
	return u, nil
}

// GetByID fetches a user by ID. Returns user or error if not found.
func (s *PostgresUserStore) GetByID(ctx context.Context, id string) (*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at, mfa_secret, mfa_enabled, backup_codes FROM users WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	u := &User{}
	var roles []string
	var attributes map[string]string
	if err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt, &u.MFASecret, &u.MFAEnabled, &u.BackupCodes); err != nil {
		return nil, errors.New("user not found")
	}
	u.Roles = roles
	u.Attributes = attributes
	return u, nil
}

// Create inserts a new user. Returns error if insert fails.
func (s *PostgresUserStore) Create(ctx context.Context, u *User) error {
	const q = `INSERT INTO users (id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at, mfa_secret, mfa_enabled, backup_codes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	now := time.Now().UTC()
	_, err := s.DB.Exec(ctx, q, u.ID, u.TenantID, u.Username, u.Email, u.PasswordHash, u.Roles, u.Attributes, now, now, u.MFASecret, u.MFAEnabled, u.BackupCodes)
	if err != nil {
		return errors.New("failed to create user")
	}
	u.CreatedAt = now
	u.UpdatedAt = now
	return nil
}

// Update modifies an existing user. Returns error if update fails.
func (s *PostgresUserStore) Update(ctx context.Context, u *User) error {
	const q = `UPDATE users SET tenant_id = $2, username = $3, email = $4, password_hash = $5, roles = $6, attributes = $7, updated_at = $8, mfa_secret = $9, mfa_enabled = $10, backup_codes = $11 WHERE id = $1`
	now := time.Now().UTC()
	_, err := s.DB.Exec(ctx, q, u.ID, u.TenantID, u.Username, u.Email, u.PasswordHash, u.Roles, u.Attributes, now, u.MFASecret, u.MFAEnabled, u.BackupCodes)
	if err != nil {
		return errors.New("failed to update user")
	}
	u.UpdatedAt = now
	return nil
}

// Delete removes a user by ID. Returns error if delete fails.
func (s *PostgresUserStore) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM users WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		return errors.New("failed to delete user")
	}
	return nil
}

// ListByTenantID returns all users for a given tenant. Returns error if query fails.
func (s *PostgresUserStore) ListByTenantID(ctx context.Context, tenantID string) ([]*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at, mfa_secret, mfa_enabled, backup_codes FROM users WHERE tenant_id = $1`
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
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt, &u.MFASecret, &u.MFAEnabled, &u.BackupCodes); err != nil {
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

// CreateRefreshToken inserts a new refresh token. Returns error if insert fails.
func (s *PostgresUserStore) CreateRefreshToken(ctx context.Context, t *RefreshToken) error {
	const q = `INSERT INTO refresh_tokens (token_id, user_id, tenant_id, token, expires_at, created_at, revoked) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.DB.Exec(ctx, q, t.TokenID, t.UserID, t.TenantID, t.Token, t.ExpiresAt, t.CreatedAt, t.Revoked)
	return err
}

// GetRefreshToken fetches a refresh token by token string. Returns token or error if not found.
func (s *PostgresUserStore) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	const q = `SELECT token_id, user_id, tenant_id, token, expires_at, created_at, revoked FROM refresh_tokens WHERE token = $1`
	row := s.DB.QueryRow(ctx, q, token)
	t := &RefreshToken{}
	if err := row.Scan(&t.TokenID, &t.UserID, &t.TenantID, &t.Token, &t.ExpiresAt, &t.CreatedAt, &t.Revoked); err != nil {
		return nil, err
	}
	return t, nil
}

// RevokeRefreshToken sets a refresh token as revoked. Returns error if update fails.
func (s *PostgresUserStore) RevokeRefreshToken(ctx context.Context, token string) error {
	const q = `UPDATE refresh_tokens SET revoked = true WHERE token = $1`
	_, err := s.DB.Exec(ctx, q, token)
	return err
}

// RevokeAllRefreshTokensForUser revokes all refresh tokens for a user. Returns error if update fails.
func (s *PostgresUserStore) RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error {
	const q = `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	return err
}

// CreatePasswordResetToken inserts a new password reset token. Returns error if insert fails.
func (s *PostgresUserStore) CreatePasswordResetToken(ctx context.Context, t *PasswordResetToken) error {
	const q = `INSERT INTO password_reset_tokens (token, user_id, tenant_id, expires_at, used, created_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.DB.Exec(ctx, q, t.Token, t.UserID, t.TenantID, t.ExpiresAt, t.Used, t.CreatedAt)
	return err
}

// GetPasswordResetToken fetches a password reset token by token string. Returns token or error if not found.
func (s *PostgresUserStore) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	const q = `SELECT token, user_id, tenant_id, expires_at, used, created_at FROM password_reset_tokens WHERE token = $1`
	row := s.DB.QueryRow(ctx, q, token)
	t := &PasswordResetToken{}
	if err := row.Scan(&t.Token, &t.UserID, &t.TenantID, &t.ExpiresAt, &t.Used, &t.CreatedAt); err != nil {
		return nil, err
	}
	return t, nil
}

// MarkPasswordResetTokenUsed marks a password reset token as used. Returns error if update fails.
func (s *PostgresUserStore) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	const q = `UPDATE password_reset_tokens SET used = true WHERE token = $1`
	_, err := s.DB.Exec(ctx, q, token)
	return err
}

// CreateEmailVerificationToken inserts a new email verification token. Returns error if insert fails.
func (s *PostgresUserStore) CreateEmailVerificationToken(ctx context.Context, t *EmailVerificationToken) error {
	const q = `INSERT INTO email_verification_tokens (token, user_id, tenant_id, expires_at, used, created_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.DB.Exec(ctx, q, t.Token, t.UserID, t.TenantID, t.ExpiresAt, t.Used, t.CreatedAt)
	return err
}

// GetEmailVerificationToken fetches an email verification token by token string. Returns token or error if not found.
func (s *PostgresUserStore) GetEmailVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error) {
	const q = `SELECT token, user_id, tenant_id, expires_at, used, created_at FROM email_verification_tokens WHERE token = $1`
	row := s.DB.QueryRow(ctx, q, token)
	t := &EmailVerificationToken{}
	if err := row.Scan(&t.Token, &t.UserID, &t.TenantID, &t.ExpiresAt, &t.Used, &t.CreatedAt); err != nil {
		return nil, err
	}
	return t, nil
}

// MarkEmailVerificationTokenUsed marks an email verification token as used. Returns error if update fails.
func (s *PostgresUserStore) MarkEmailVerificationTokenUsed(ctx context.Context, token string) error {
	const q = `UPDATE email_verification_tokens SET used = true WHERE token = $1`
	_, err := s.DB.Exec(ctx, q, token)
	return err
}

// GetByEmail fetches a user by email. Returns user or error if not found.
func (s *PostgresUserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	const q = `SELECT id, tenant_id, username, email, password_hash, roles, attributes, created_at, updated_at, email_verified, mfa_secret, mfa_enabled, backup_codes FROM users WHERE email = $1`
	row := s.DB.QueryRow(ctx, q, email)
	var u User
	var roles []string
	var attributes map[string]string
	if err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.PasswordHash, &roles, &attributes, &u.CreatedAt, &u.UpdatedAt, &u.EmailVerified, &u.MFASecret, &u.MFAEnabled, &u.BackupCodes); err != nil {
		return nil, err
	}
	u.Roles = roles
	u.Attributes = attributes
	return &u, nil
}

// UserDeviceStore implementation (Postgres)
func (s *PostgresUserStore) CreateDevice(ctx context.Context, d *UserDevice) error {
	const q = `INSERT INTO user_devices (device_id, user_id, refresh_token_id, user_agent, ip, created_at, last_seen, revoked, name) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := s.DB.Exec(ctx, q, d.DeviceID, d.UserID, d.RefreshTokenID, d.UserAgent, d.IP, d.CreatedAt, d.LastSeen, d.Revoked, d.Name)
	return err
}

func (s *PostgresUserStore) UpdateDevice(ctx context.Context, d *UserDevice) error {
	const q = `UPDATE user_devices SET refresh_token_id = $2, user_agent = $3, ip = $4, last_seen = $5, revoked = $6, name = $7 WHERE device_id = $1`
	_, err := s.DB.Exec(ctx, q, d.DeviceID, d.RefreshTokenID, d.UserAgent, d.IP, d.LastSeen, d.Revoked, d.Name)
	return err
}

func (s *PostgresUserStore) GetDeviceByID(ctx context.Context, deviceID string) (*UserDevice, error) {
	const q = `SELECT device_id, user_id, refresh_token_id, user_agent, ip, created_at, last_seen, revoked, name FROM user_devices WHERE device_id = $1`
	row := s.DB.QueryRow(ctx, q, deviceID)
	d := &UserDevice{}
	if err := row.Scan(&d.DeviceID, &d.UserID, &d.RefreshTokenID, &d.UserAgent, &d.IP, &d.CreatedAt, &d.LastSeen, &d.Revoked, &d.Name); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *PostgresUserStore) ListDevicesByUserID(ctx context.Context, userID string) ([]*UserDevice, error) {
	const q = `SELECT device_id, user_id, refresh_token_id, user_agent, ip, created_at, last_seen, revoked, name FROM user_devices WHERE user_id = $1 ORDER BY last_seen DESC`
	rows, err := s.DB.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserDevice
	for rows.Next() {
		d := &UserDevice{}
		if err := rows.Scan(&d.DeviceID, &d.UserID, &d.RefreshTokenID, &d.UserAgent, &d.IP, &d.CreatedAt, &d.LastSeen, &d.Revoked, &d.Name); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *PostgresUserStore) RevokeDevice(ctx context.Context, deviceID string) error {
	const q = `UPDATE user_devices SET revoked = true WHERE device_id = $1`
	_, err := s.DB.Exec(ctx, q, deviceID)
	return err
}

func (s *PostgresUserStore) RevokeAllDevicesForUser(ctx context.Context, userID string) error {
	const q = `UPDATE user_devices SET revoked = true WHERE user_id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	return err
}

// --- UserOrgProjectRoleStore implementation (Postgres) ---

func (s *PostgresUserStore) CreateRole(ctx context.Context, r *UserOrgProjectRole) error {
	const q = `INSERT INTO user_org_project_roles (id, user_id, org_id, project_id, role, permissions, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	_, err := s.DB.Exec(ctx, q, r.ID, r.UserID, r.OrgID, r.ProjectID, r.Role, r.Permissions, r.CreatedAt, r.UpdatedAt)
	return err
}

func (s *PostgresUserStore) UpdateRole(ctx context.Context, r *UserOrgProjectRole) error {
	const q = `UPDATE user_org_project_roles SET user_id=$2, org_id=$3, project_id=$4, role=$5, permissions=$6, updated_at=$7 WHERE id=$1`
	_, err := s.DB.Exec(ctx, q, r.ID, r.UserID, r.OrgID, r.ProjectID, r.Role, r.Permissions, r.UpdatedAt)
	return err
}

func (s *PostgresUserStore) DeleteRole(ctx context.Context, id string) error {
	const q = `DELETE FROM user_org_project_roles WHERE id=$1`
	_, err := s.DB.Exec(ctx, q, id)
	return err
}

func (s *PostgresUserStore) GetRoleByID(ctx context.Context, id string) (*UserOrgProjectRole, error) {
	const q = `SELECT id, user_id, org_id, project_id, role, permissions, created_at, updated_at FROM user_org_project_roles WHERE id=$1`
	row := s.DB.QueryRow(ctx, q, id)
	r := &UserOrgProjectRole{}
	var orgID, projectID *string
	if err := row.Scan(&r.ID, &r.UserID, &orgID, &projectID, &r.Role, &r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.OrgID = orgID
	r.ProjectID = projectID
	return r, nil
}

func (s *PostgresUserStore) ListRolesByUser(ctx context.Context, userID string) ([]*UserOrgProjectRole, error) {
	const q = `SELECT id, user_id, org_id, project_id, role, permissions, created_at, updated_at FROM user_org_project_roles WHERE user_id=$1`
	rows, err := s.DB.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserOrgProjectRole
	for rows.Next() {
		r := &UserOrgProjectRole{}
		var orgID, projectID *string
		if err := rows.Scan(&r.ID, &r.UserID, &orgID, &projectID, &r.Role, &r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.OrgID = orgID
		r.ProjectID = projectID
		out = append(out, r)
	}
	return out, nil
}

func (s *PostgresUserStore) ListRolesByOrg(ctx context.Context, orgID string) ([]*UserOrgProjectRole, error) {
	const q = `SELECT id, user_id, org_id, project_id, role, permissions, created_at, updated_at FROM user_org_project_roles WHERE org_id=$1`
	rows, err := s.DB.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserOrgProjectRole
	for rows.Next() {
		r := &UserOrgProjectRole{}
		var orgIDPtr, projectID *string
		if err := rows.Scan(&r.ID, &r.UserID, &orgIDPtr, &projectID, &r.Role, &r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.OrgID = orgIDPtr
		r.ProjectID = projectID
		out = append(out, r)
	}
	return out, nil
}

func (s *PostgresUserStore) ListRolesByProject(ctx context.Context, projectID string) ([]*UserOrgProjectRole, error) {
	const q = `SELECT id, user_id, org_id, project_id, role, permissions, created_at, updated_at FROM user_org_project_roles WHERE project_id=$1`
	rows, err := s.DB.Query(ctx, q, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*UserOrgProjectRole
	for rows.Next() {
		r := &UserOrgProjectRole{}
		var orgID, projectIDPtr *string
		if err := rows.Scan(&r.ID, &r.UserID, &orgID, &projectIDPtr, &r.Role, &r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.OrgID = orgID
		r.ProjectID = projectIDPtr
		out = append(out, r)
	}
	return out, nil
}

func (s *PostgresUserStore) FindRole(ctx context.Context, userID, orgID, projectID, role string) (*UserOrgProjectRole, error) {
	const q = `SELECT id, user_id, org_id, project_id, role, permissions, created_at, updated_at FROM user_org_project_roles WHERE user_id=$1 AND org_id IS NOT DISTINCT FROM $2 AND project_id IS NOT DISTINCT FROM $3 AND role=$4`
	row := s.DB.QueryRow(ctx, q, userID, orgID, projectID, role)
	r := &UserOrgProjectRole{}
	var orgIDPtr, projectIDPtr *string
	if err := row.Scan(&r.ID, &r.UserID, &orgIDPtr, &projectIDPtr, &r.Role, &r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.OrgID = orgIDPtr
	r.ProjectID = projectIDPtr
	return r, nil
}

// CreateRolesTx creates multiple roles in a single transaction. Returns error if any insert fails.
func (s *PostgresUserStore) CreateRolesTx(ctx context.Context, tx pgx.Tx, roles []*UserOrgProjectRole) error {
	const q = `INSERT INTO user_org_project_roles (id, user_id, org_id, project_id, role, permissions, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	for _, r := range roles {
		_, err := tx.Exec(ctx, q, r.ID, r.UserID, r.OrgID, r.ProjectID, r.Role, r.Permissions, r.CreatedAt, r.UpdatedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteRolesTx deletes multiple roles in a single transaction. Returns error if any delete fails.
func (s *PostgresUserStore) DeleteRolesTx(ctx context.Context, tx pgx.Tx, roleIDs []string) error {
	const q = `DELETE FROM user_org_project_roles WHERE id=$1`
	for _, id := range roleIDs {
		_, err := tx.Exec(ctx, q, id)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateRolesTx updates multiple roles in a single transaction. Returns error if any update fails.
func (s *PostgresUserStore) UpdateRolesTx(ctx context.Context, tx pgx.Tx, roles []*UserOrgProjectRole) error {
	const q = `UPDATE user_org_project_roles SET user_id=$2, org_id=$3, project_id=$4, role=$5, permissions=$6, updated_at=$7 WHERE id=$1`
	for _, r := range roles {
		_, err := tx.Exec(ctx, q, r.ID, r.UserID, r.OrgID, r.ProjectID, r.Role, r.Permissions, r.UpdatedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListAllUserRolesPermissions returns all users with all their roles/permissions (org/project/global)
func (s *PostgresUserStore) ListAllUserRolesPermissions(ctx context.Context) ([]*UserRolesPermissions, error) {
	const userQ = `SELECT id, username, email FROM users`
	const roleQ = `SELECT user_id, id, org_id, project_id, role, permissions, created_at, updated_at FROM user_org_project_roles`
	rows, err := s.DB.Query(ctx, userQ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make(map[string]*UserRolesPermissions)
	for rows.Next() {
		var u UserRolesPermissions
		if err := rows.Scan(&u.UserID, &u.Username, &u.Email); err != nil {
			return nil, err
		}
		u.Roles = []UserOrgProjectRole{}
		users[u.UserID] = &u
	}
	roleRows, err := s.DB.Query(ctx, roleQ)
	if err != nil {
		return nil, err
	}
	defer roleRows.Close()
	for roleRows.Next() {
		var r UserOrgProjectRole
		var userID string
		if err := roleRows.Scan(&userID, &r.ID, &r.OrgID, &r.ProjectID, &r.Role, &r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if u, ok := users[userID]; ok {
			u.Roles = append(u.Roles, r)
		}
	}
	result := make([]*UserRolesPermissions, 0, len(users))
	for _, u := range users {
		result = append(result, u)
	}
	return result, nil
}
