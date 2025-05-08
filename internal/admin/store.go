package admin

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
	"github.com/subinc/subinc-backend/enterprise/notifications"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

func NewPostgresAdminStore(db *pgxpool.Pool) *PostgresAdminStore {
	return &PostgresAdminStore{DB: db}
}

func (s *PostgresAdminStore) ListUsers() ([]interface{}, error) {
	const q = `SELECT id, username, email, roles, created_at, updated_at FROM admin_users`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query admin users", logger.ErrorField(err))
		return nil, errors.New("failed to query admin users")
	}
	defer rows.Close()
	var users []interface{}
	for rows.Next() {
		var id, username, email string
		var roles []string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &username, &email, &roles, &createdAt, &updatedAt); err != nil {
			logger.LogError("failed to scan admin user row", logger.ErrorField(err))
			return nil, errors.New("failed to scan admin user row:" + err.Error())
		}
		users = append(users, map[string]interface{}{
			"id":         id,
			"username":   username,
			"email":      email,
			"roles":      roles,
			"created_at": createdAt.Format(time.RFC3339),
			"updated_at": updatedAt.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating admin user rows", logger.ErrorField(err))
		return nil, errors.New("error iterating admin user rows")
	}
	return users, nil
}

func (s *PostgresAdminStore) ListTenants() ([]interface{}, error) {
	const q = `SELECT id, name, settings, created_at, updated_at FROM tenants`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query tenants", logger.ErrorField(err))
		return nil, errors.New("failed to query tenants")
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var id, name, settings string
		var createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &settings, &createdAt, &updatedAt); err != nil {
			logger.LogError("failed to scan tenant row", logger.ErrorField(err))
			return nil, errors.New("failed to scan tenant row")
		}
		tenants = append(tenants, map[string]interface{}{
			"id":         id,
			"name":       name,
			"settings":   settings,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating tenant rows", logger.ErrorField(err))
		return nil, errors.New("error iterating tenant rows")
	}
	return tenants, nil
}

func (s *PostgresAdminStore) ListRoles() ([]interface{}, error) {
	const q = `SELECT id, name, permissions FROM admin_roles`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query admin roles", logger.ErrorField(err))
		return nil, errors.New("failed to query admin roles")
	}
	defer rows.Close()
	var roles []interface{}
	for rows.Next() {
		var id, name string
		var permissions []string
		if err := rows.Scan(&id, &name, &permissions); err != nil {
			logger.LogError("failed to scan admin role row", logger.ErrorField(err))
			return nil, errors.New("failed to scan admin role row")
		}
		roles = append(roles, map[string]interface{}{
			"id":          id,
			"name":        name,
			"permissions": permissions,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating admin role rows", logger.ErrorField(err))
		return nil, errors.New("error iterating admin role rows")
	}
	return roles, nil
}

func (s *PostgresAdminStore) ListPermissions() ([]interface{}, error) {
	const q = `SELECT id, name FROM admin_permissions`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query admin permissions", logger.ErrorField(err))
		return nil, errors.New("failed to query admin permissions")
	}
	defer rows.Close()
	var perms []interface{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			logger.LogError("failed to scan admin permission row", logger.ErrorField(err))
			return nil, errors.New("failed to scan admin permission row")
		}
		perms = append(perms, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating admin permission rows", logger.ErrorField(err))
		return nil, errors.New("error iterating admin permission rows")
	}
	return perms, nil
}

func (s *PostgresAdminStore) BillingSummary() (interface{}, error) {
	const q = `SELECT COALESCE(SUM(amount),0) as total, COALESCE(MAX(currency),'USD') as currency FROM billing_records WHERE status = 'paid'`
	row := s.DB.QueryRow(context.Background(), q)
	var total float64
	var currency string
	if err := row.Scan(&total, &currency); err != nil {
		logger.LogError("failed to aggregate billing summary", logger.ErrorField(err))
		return nil, errors.New("failed to aggregate billing summary")
	}
	return map[string]interface{}{"total": total, "currency": currency}, nil
}

func (s *PostgresAdminStore) SystemHealth() (interface{}, error) {
	ctx := context.Background()
	// Check DB connection
	if err := s.DB.Ping(ctx); err != nil {
		logger.LogError("failed to ping database", logger.ErrorField(err))
		return map[string]interface{}{"status": "unhealthy", "db": "down"}, nil
	}
	// Check critical table existence
	tables := []string{"admin_users", "tenants", "billing_records"}
	for _, tbl := range tables {
		q := "SELECT 1 FROM " + tbl + " LIMIT 1"
		if _, err := s.DB.Exec(ctx, q); err != nil {
			logger.LogError("failed to check table existence", logger.ErrorField(err))
			return map[string]interface{}{"status": "unhealthy", "db": "ok", "missing_table": tbl}, nil
		}
	}
	return map[string]interface{}{"status": "healthy", "db": "ok"}, nil
}

func (s *PostgresAdminStore) ListSessions() ([]interface{}, error) {
	const q = `SELECT id, user_id, created_at, expires_at, ip_address FROM admin_sessions WHERE expires_at > NOW()`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query admin sessions", logger.ErrorField(err))
		return nil, errors.New("failed to query admin sessions")
	}
	defer rows.Close()
	var sessions []interface{}
	for rows.Next() {
		var id, userID, ip string
		var createdAt, expiresAt string
		if err := rows.Scan(&id, &userID, &createdAt, &expiresAt, &ip); err != nil {
			logger.LogError("failed to scan admin session row", logger.ErrorField(err))
			return nil, errors.New("failed to scan admin session row")
		}
		sessions = append(sessions, map[string]interface{}{
			"id":         id,
			"user_id":    userID,
			"created_at": createdAt,
			"expires_at": expiresAt,
			"ip_address": ip,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating admin session rows", logger.ErrorField(err))
		return nil, errors.New("error iterating admin session rows")
	}
	return sessions, nil
}

func (s *PostgresAdminStore) ImpersonateUser(userID string) (interface{}, error) {
	ctx := context.Background()
	// Create a new session for the impersonated user
	const insertSession = `INSERT INTO admin_sessions (user_id, created_at, expires_at, ip_address) VALUES ($1, NOW(), NOW() + INTERVAL '1 hour', '127.0.0.1') RETURNING id, created_at, expires_at, ip_address`
	var id, createdAt, expiresAt, ip string
	if err := s.DB.QueryRow(ctx, insertSession, userID).Scan(&id, &createdAt, &expiresAt, &ip); err != nil {
		logger.LogError("failed to create impersonation session", logger.ErrorField(err))
		return nil, errors.New("failed to create impersonation session")
	}
	// Log the impersonation event
	const logEvent = `INSERT INTO audit_logs (actor_id, action, resource, details, created_at, hash, prev_hash) VALUES ($1, 'impersonate', 'admin_sessions', $2, NOW(), '', '')`
	if _, err := s.DB.Exec(ctx, logEvent, userID, "Impersonation session created"); err != nil {
		logger.LogError("failed to log impersonation event", logger.ErrorField(err))
		return nil, errors.New("failed to log impersonation event")
	}
	return map[string]interface{}{
		"id":         id,
		"user_id":    userID,
		"created_at": createdAt,
		"expires_at": expiresAt,
		"ip_address": ip,
	}, nil
}

func (s *PostgresAdminStore) SupportTools() (interface{}, error) {
	const q = `SELECT name, status FROM support_tools`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query support tools", logger.ErrorField(err))
		return nil, errors.New("failed to query support tools")
	}
	defer rows.Close()
	var tools []map[string]interface{}
	for rows.Next() {
		var name, status string
		if err := rows.Scan(&name, &status); err != nil {
			logger.LogError("failed to scan support tool row", logger.ErrorField(err))
			return nil, errors.New("failed to scan support tool row")
		}
		tools = append(tools, map[string]interface{}{
			"name":   name,
			"status": status,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating support tool rows", logger.ErrorField(err))
		return nil, errors.New("error iterating support tool rows")
	}
	return map[string]interface{}{"tools": tools}, nil
}

func (s *PostgresAdminStore) RBACStatus() (interface{}, error) {
	const q = `SELECT value FROM system_config WHERE key = 'rbac_enabled'`
	row := s.DB.QueryRow(context.Background(), q)
	var value string
	if err := row.Scan(&value); err != nil {
		logger.LogError("failed to query RBAC status", logger.ErrorField(err))
		return nil, errors.New("failed to query RBAC status")
	}
	return map[string]interface{}{"rbac": value == "true"}, nil
}

func (s *PostgresAdminStore) StepUpAuth(userID string) (interface{}, error) {
	const q = `UPDATE admin_users SET stepup_required = TRUE WHERE id = $1 RETURNING id`
	row := s.DB.QueryRow(context.Background(), q, userID)
	var id string
	if err := row.Scan(&id); err != nil {
		logger.LogError("failed to mark user for step-up auth", logger.ErrorField(err))
		return nil, errors.New("failed to mark user for step-up auth")
	}
	return map[string]interface{}{"user_id": id, "stepup": true}, nil
}

func (s *PostgresAdminStore) DelegatedAdminStatus() (interface{}, error) {
	const q = `SELECT value FROM system_config WHERE key = 'delegated_admin_enabled'`
	row := s.DB.QueryRow(context.Background(), q)
	var value string
	if err := row.Scan(&value); err != nil {
		logger.LogError("failed to query delegated admin status", logger.ErrorField(err))
		return nil, errors.New("failed to query delegated admin status")
	}
	return map[string]interface{}{"delegated_admin": value == "true"}, nil
}

func (s *PostgresAdminStore) SCIMStatus() (interface{}, error) {
	const q = `SELECT value FROM system_config WHERE key = 'scim_enabled'`
	row := s.DB.QueryRow(context.Background(), q)
	var value string
	if err := row.Scan(&value); err != nil {
		logger.LogError("failed to query SCIM status", logger.ErrorField(err))
		return nil, errors.New("failed to query SCIM status")
	}
	return map[string]interface{}{"scim": value == "true"}, nil
}

func (s *PostgresAdminStore) AuditAnomalies() (interface{}, error) {
	ctx := context.Background()
	// Example: Find audit logins outside business hours (8am-6pm)
	const q = `SELECT id, actor_id, action, resource, details, created_at FROM audit_logs WHERE action = 'login' AND (EXTRACT(HOUR FROM created_at) < 8 OR EXTRACT(HOUR FROM created_at) > 18) ORDER BY created_at DESC LIMIT 100`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("failed to query audit anomalies", logger.ErrorField(err))
		return nil, errors.New("failed to query audit anomalies")
	}
	defer rows.Close()
	var anomalies []map[string]interface{}
	for rows.Next() {
		var id, actorID, action, resource, details string
		var createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			logger.LogError("failed to scan audit anomaly row", logger.ErrorField(err))
			return nil, errors.New("failed to scan audit anomaly row")
		}
		anomalies = append(anomalies, map[string]interface{}{
			"id":         id,
			"actor_id":   actorID,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating audit anomaly rows", logger.ErrorField(err))
		return nil, errors.New("error iterating audit anomaly rows")
	}
	return map[string]interface{}{"anomalies": anomalies}, nil
}

func (s *PostgresAdminStore) RateLimits() (interface{}, error) {
	const q = `SELECT endpoint, limit_per_minute, current_usage FROM rate_limits WHERE role = 'admin'`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query rate limits", logger.ErrorField(err))
		return nil, errors.New("failed to query rate limits")
	}
	defer rows.Close()
	var limits []map[string]interface{}
	for rows.Next() {
		var endpoint string
		var limitPerMinute, currentUsage int
		if err := rows.Scan(&endpoint, &limitPerMinute, &currentUsage); err != nil {
			logger.LogError("failed to scan rate limit row", logger.ErrorField(err))
			return nil, errors.New("failed to scan rate limit row")
		}
		limits = append(limits, map[string]interface{}{
			"endpoint":         endpoint,
			"limit_per_minute": limitPerMinute,
			"current_usage":    currentUsage,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating rate limit rows", logger.ErrorField(err))
		return nil, errors.New("error iterating rate limit rows")
	}
	return map[string]interface{}{"rate_limits": limits}, nil
}

func (s *PostgresAdminStore) AbuseDetection() (interface{}, error) {
	const q = `SELECT id, user_id, event_type, details, created_at FROM abuse_events WHERE created_at > NOW() - INTERVAL '24 hours'`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query abuse events", logger.ErrorField(err))
		return nil, errors.New("failed to query abuse events")
	}
	defer rows.Close()
	var events []map[string]interface{}
	for rows.Next() {
		var id, userID, eventType, details string
		var createdAt string
		if err := rows.Scan(&id, &userID, &eventType, &details, &createdAt); err != nil {
			logger.LogError("failed to scan abuse event row", logger.ErrorField(err))
			return nil, errors.New("failed to scan abuse event row")
		}
		events = append(events, map[string]interface{}{
			"id":         id,
			"user_id":    userID,
			"event_type": eventType,
			"details":    details,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating abuse event rows", logger.ErrorField(err))
		return nil, errors.New("error iterating abuse event rows")
	}
	return map[string]interface{}{"abuse_events": events, "abuse": len(events) > 0}, nil
}

func (s *PostgresAdminStore) Alerts() (interface{}, error) {
	const q = `SELECT id, type, message, severity, created_at FROM alerts WHERE active = TRUE`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query alerts", logger.ErrorField(err))
		return nil, errors.New("failed to query alerts")
	}
	defer rows.Close()
	var alerts []map[string]interface{}
	for rows.Next() {
		var id, alertType, message, severity, createdAt string
		if err := rows.Scan(&id, &alertType, &message, &severity, &createdAt); err != nil {
			logger.LogError("failed to scan alert row", logger.ErrorField(err))
			return nil, errors.New("failed to scan alert row")
		}
		alerts = append(alerts, map[string]interface{}{
			"id":         id,
			"type":       alertType,
			"message":    message,
			"severity":   severity,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating alert rows", logger.ErrorField(err))
		return nil, errors.New("error iterating alert rows")
	}
	return map[string]interface{}{"alerts": alerts}, nil
}

func (s *PostgresAdminStore) SecretsStatus() (interface{}, error) {
	ctx := context.Background()
	const q = `SELECT key_id, status, last_rotated FROM secrets_manager WHERE active = TRUE`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("failed to query secrets status", logger.ErrorField(err))
		return nil, errors.New("failed to query secrets status")
	}
	defer rows.Close()
	var secrets []SecretInfo
	for rows.Next() {
		var keyID, status string
		var lastRotated time.Time
		if err := rows.Scan(&keyID, &status, &lastRotated); err != nil {
			logger.LogError("failed to scan secrets row", logger.ErrorField(err))
			return nil, errors.New("failed to scan secrets row")
		}
		secrets = append(secrets, SecretInfo{
			KeyID:       keyID,
			Status:      status,
			LastRotated: lastRotated,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating secrets rows", logger.ErrorField(err))
		return nil, errors.New("error iterating secrets rows")
	}
	return map[string]interface{}{"secrets": secrets}, nil
}

func (s *PostgresAdminStore) SystemConfig() (interface{}, error) {
	const q = `SELECT key, value, updated_at FROM system_config`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query system config", logger.ErrorField(err))
		return nil, errors.New("failed to query system config")
	}
	defer rows.Close()
	var configs []map[string]interface{}
	for rows.Next() {
		var key, value, updatedAt string
		if err := rows.Scan(&key, &value, &updatedAt); err != nil {
			logger.LogError("failed to scan system config row", logger.ErrorField(err))
			return nil, errors.New("failed to scan system config row")
		}
		configs = append(configs, map[string]interface{}{
			"key":        key,
			"value":      value,
			"updated_at": updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating system config rows", logger.ErrorField(err))
		return nil, errors.New("error iterating system config rows")
	}
	return map[string]interface{}{"config": configs}, nil
}

func (s *PostgresAdminStore) FeatureFlags() ([]interface{}, error) {
	const q = `SELECT flag, enabled, updated_at FROM feature_flags`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query feature flags", logger.ErrorField(err))
		return nil, errors.New("failed to query feature flags")
	}
	defer rows.Close()
	var flags []interface{}
	for rows.Next() {
		var f FeatureFlag
		if err := rows.Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
			logger.LogError("failed to scan feature flag row", logger.ErrorField(err))
			return nil, errors.New("failed to scan feature flag row")
		}
		flags = append(flags, f)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating feature flag rows", logger.ErrorField(err))
		return nil, errors.New("error iterating feature flag rows")
	}
	return flags, nil
}

func (s *PostgresAdminStore) MaintenanceMode() (interface{}, error) {
	ctx := context.Background()
	const key = "maintenance_mode"
	var raw string
	var updatedAt time.Time
	err := s.DB.QueryRow(ctx, `SELECT value, updated_at FROM system_config WHERE key = $1`, key).Scan(&raw, &updatedAt)
	if err != nil && err.Error() != "no rows in result set" {
		logger.LogError("failed to fetch maintenance mode status", logger.ErrorField(err))
		return nil, errors.New("failed to fetch maintenance mode status")
	}
	var status MaintenanceModeStatus
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &status); err != nil {
			logger.LogError("invalid maintenance mode json", logger.ErrorField(err))
			return nil, errors.New("invalid maintenance mode json")
		}
	}
	status.UpdatedAt = updatedAt
	return &status, nil
}

func (s *PostgresAdminStore) RealTimeMonitoring() (interface{}, error) {
	const q = `SELECT id, event_type, message, created_at FROM monitoring_events WHERE created_at > NOW() - INTERVAL '5 minutes'`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query monitoring events", logger.ErrorField(err))
		return nil, errors.New("failed to query monitoring events")
	}
	defer rows.Close()
	var events []map[string]interface{}
	for rows.Next() {
		var id, eventType, message, createdAt string
		if err := rows.Scan(&id, &eventType, &message, &createdAt); err != nil {
			logger.LogError("failed to scan monitoring event row", logger.ErrorField(err))
			return nil, errors.New("failed to scan monitoring event row")
		}
		events = append(events, map[string]interface{}{
			"id":         id,
			"event_type": eventType,
			"message":    message,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating monitoring event rows", logger.ErrorField(err))
		return nil, errors.New("error iterating monitoring event rows")
	}
	return map[string]interface{}{"monitoring": events}, nil
}

func (s *PostgresAdminStore) Create(ctx context.Context, u *AdminUser) error {
	if u.Username == "" || u.Email == "" || u.Password == "" {
		logger.LogError("invalid admin user input",
			logger.String("username", u.Username),
			logger.String("email", u.Email),
		)
		return errors.New("username, email, and password required")
	}
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	}

	hash, err := secrets.HashPassword(u.Password)
	if err != nil {
		logger.LogError("failed to hash password",
			logger.ErrorField(err),
			logger.String("username", u.Username),
			logger.String("email", u.Email),
			logger.String("id", u.ID),
		)
		return errors.New("failed to hash password")
	}
	u.PasswordHash = hash
	u.Password = "" // never store plain password

	const q = `INSERT INTO admin_users (id, username, email, password_hash, roles, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = s.DB.Exec(ctx, q, u.ID, u.Username, u.Email, u.PasswordHash, u.Roles, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		logger.LogError("failed to create admin user",
			logger.ErrorField(err),
			logger.String("username", u.Username),
			logger.String("email", u.Email),
			logger.String("id", u.ID),
		)
		return errors.New("failed to create admin user: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdateUser(user *AdminUser) error {
	return s.Update(context.Background(), user)
}

func (s *PostgresAdminStore) DeleteUser(id string) error {
	return s.Delete(context.Background(), id)
}

func (s *PostgresAdminStore) CreateTenant(tenant *Tenant) error {
	const q = `INSERT INTO tenants (id, name, settings, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())`
	_, err := s.DB.Exec(context.Background(), q, tenant.ID, tenant.Name, tenant.Settings)
	if err != nil {
		logger.LogError("failed to create tenant", logger.ErrorField(err), logger.String("id", tenant.ID), logger.String("name", tenant.Name))
		return errors.New("failed to create tenant: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdateTenant(tenant *Tenant) error {
	const q = `UPDATE tenants SET name=$2, settings=$3, updated_at=NOW() WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, tenant.ID, tenant.Name, tenant.Settings)
	if err != nil {
		logger.LogError("failed to update tenant", logger.ErrorField(err), logger.String("id", tenant.ID), logger.String("name", tenant.Name))
		return errors.New("failed to update tenant: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) DeleteTenant(id string) error {
	const q = `DELETE FROM tenants WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	if err != nil {
		logger.LogError("failed to delete tenant", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete tenant: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) CreateRole(role *AdminRole) error {
	const q = `INSERT INTO admin_roles (id, name, permissions) VALUES ($1, $2, $3)`
	_, err := s.DB.Exec(context.Background(), q, role.ID, role.Name, role.Permissions)
	if err != nil {
		logger.LogError("failed to create role", logger.ErrorField(err), logger.String("id", role.ID), logger.String("name", role.Name))
		return errors.New("failed to create role: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdateRole(role *AdminRole) error {
	const q = `UPDATE admin_roles SET name=$2, permissions=$3 WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, role.ID, role.Name, role.Permissions)
	if err != nil {
		logger.LogError("failed to update role", logger.ErrorField(err), logger.String("id", role.ID), logger.String("name", role.Name))
		return errors.New("failed to update role: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) DeleteRole(id string) error {
	const q = `DELETE FROM admin_roles WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	if err != nil {
		logger.LogError("failed to delete role", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete role: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) CreatePermission(perm *AdminPermission) error {
	const q = `INSERT INTO admin_permissions (id, name) VALUES ($1, $2)`
	_, err := s.DB.Exec(context.Background(), q, perm.ID, perm.Name)
	if err != nil {
		logger.LogError("failed to create permission", logger.ErrorField(err), logger.String("id", perm.ID), logger.String("name", perm.Name))
		return errors.New("failed to create permission: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdatePermission(perm *AdminPermission) error {
	const q = `UPDATE admin_permissions SET name=$2 WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, perm.ID, perm.Name)
	if err != nil {
		logger.LogError("failed to update permission", logger.ErrorField(err), logger.String("id", perm.ID), logger.String("name", perm.Name))
		return errors.New("failed to update permission: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) DeletePermission(id string) error {
	const q = `DELETE FROM admin_permissions WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	if err != nil {
		logger.LogError("failed to delete permission", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete permission: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) RevokeUserSessions(userID string) (int, error) {
	ctx := context.Background()
	if userID == "" {
		return 0, errors.New("user_id required")
	}
	count, err := s.SessionMgr.DeleteByUserID(ctx, userID)
	if err != nil {
		logger.LogError("failed to revoke user sessions", logger.ErrorField(err), logger.String("user_id", userID))
		return 0, errors.New("failed to revoke user sessions: " + err.Error())
	}
	return count, nil
}

func (s *PostgresAdminStore) RevokeTenantSessions(tenantID string) (int, error) {
	ctx := context.Background()
	if tenantID == "" {
		logger.LogError("tenant_id required: nil input")
		return 0, errors.New("tenant_id required")
	}
	count, err := s.SessionMgr.DeleteByTenantID(ctx, tenantID)
	if err != nil {
		logger.LogError("failed to revoke tenant sessions", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return 0, errors.New("failed to revoke tenant sessions: " + err.Error())
	}
	return count, nil
}

// LogAuditEvent writes an immutable, exportable audit log entry with full compliance context
func (s *PostgresAdminStore) LogAuditEvent(eventType, action, userID string, details map[string]interface{}) error {
	ctx := context.Background()
	// Add compliance context if available
	if details == nil {
		details = map[string]interface{}{}
	}
	if v := ctx.Value("request_id"); v != nil {
		details["request_id"] = v
	}
	if v := ctx.Value("ip_address"); v != nil {
		details["ip_address"] = v
	}
	if v := ctx.Value("user_agent"); v != nil {
		details["user_agent"] = v
	}
	// Compute exportable hash for compliance
	detailsJSON, _ := json.Marshal(details)
	hash := computeAuditHash(userID, action, eventType, string(detailsJSON))
	const q = `INSERT INTO audit_logs (actor_id, action, resource, details, created_at, hash, prev_hash) VALUES ($1, $2, $3, $4, NOW(), $5, (SELECT hash FROM audit_logs ORDER BY created_at DESC LIMIT 1))`
	_, err := s.DB.Exec(ctx, q, userID, action, eventType, string(detailsJSON), hash)
	if err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err), logger.String("user_id", userID), logger.String("action", action), logger.String("event_type", eventType))
		return errors.New("failed to log audit event: " + err.Error())
	}
	return nil
}

// computeAuditHash generates a hash for audit log export/compliance
func computeAuditHash(actorID, action, resource, details string) string {
	// Use a simple SHA256 for exportable hash
	h := sha256.New()
	h.Write([]byte(actorID + action + resource + details))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *PostgresAdminStore) EnableMFA(userID string) error {
	ctx := context.Background()
	if userID == "" {
		logger.LogError("user_id required: nil input")
		return errors.New("user_id required")
	}
	const q = `UPDATE admin_users SET mfa_enabled = TRUE, mfa_reset_required = FALSE WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	if err != nil {
		logger.LogError("failed to enable MFA", logger.ErrorField(err), logger.String("user_id", userID))
		return errors.New("failed to enable MFA: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) DisableMFA(userID string) error {
	ctx := context.Background()
	if userID == "" {
		logger.LogError("user_id required: nil input")
		return errors.New("user_id required")
	}
	const q = `UPDATE admin_users SET mfa_enabled = FALSE, mfa_secret = '', mfa_reset_required = FALSE WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	if err != nil {
		logger.LogError("failed to disable MFA", logger.ErrorField(err), logger.String("user_id", userID))
		return errors.New("failed to disable MFA: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) ResetMFA(userID string) error {
	ctx := context.Background()
	if userID == "" {
		logger.LogError("user_id required: nil input")
		return errors.New("user_id required")
	}
	const q = `UPDATE admin_users SET mfa_secret = '', mfa_reset_required = TRUE WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	if err != nil {
		logger.LogError("failed to reset MFA", logger.ErrorField(err), logger.String("user_id", userID))
		return errors.New("failed to reset MFA: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) MFAStatus(userID string) (interface{}, error) {
	ctx := context.Background()
	if userID == "" {
		logger.LogError("user_id required: nil input")
		return nil, errors.New("user_id required")
	}
	const q = `SELECT mfa_enabled, mfa_reset_required FROM admin_users WHERE id = $1`
	var enabled bool
	var resetRequired bool
	err := s.DB.QueryRow(ctx, q, userID).Scan(&enabled, &resetRequired)
	if err != nil {
		logger.LogError("failed to get MFA status", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, errors.New("failed to get MFA status: " + err.Error())
	}
	return map[string]interface{}{"mfa_enabled": enabled, "mfa_reset_required": resetRequired}, nil
}

func (s *PostgresAdminStore) ListPolicies() ([]interface{}, error) {
	const q = `SELECT id, name, type, target_id, rules, created_at, updated_at FROM policies`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		logger.LogError("failed to query policies", logger.ErrorField(err))
		return nil, errors.New("failed to query policies")
	}
	defer rows.Close()
	var policies []interface{}
	for rows.Next() {
		var p Policy
		var rulesJSON string
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.TargetID, &rulesJSON, &p.CreatedAt, &p.UpdatedAt); err != nil {
			logger.LogError("failed to scan policy row", logger.ErrorField(err))
			return nil, errors.New("failed to scan policy row")
		}
		if err := json.Unmarshal([]byte(rulesJSON), &p.Rules); err != nil {
			p.Rules = map[string]interface{}{"error": "invalid rules json"}
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating policy rows", logger.ErrorField(err))
		return nil, errors.New("error iterating policy rows")
	}
	return policies, nil
}

func (s *PostgresAdminStore) GetPolicy(id string) (interface{}, error) {
	const q = `SELECT id, name, type, target_id, rules, created_at, updated_at FROM policies WHERE id = $1`
	var p Policy
	var rulesJSON string
	err := s.DB.QueryRow(context.Background(), q, id).Scan(&p.ID, &p.Name, &p.Type, &p.TargetID, &rulesJSON, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		logger.LogError("failed to get policy", logger.ErrorField(err), logger.String("id", id))
		return nil, errors.New("failed to get policy: " + err.Error())
	}
	if err := json.Unmarshal([]byte(rulesJSON), &p.Rules); err != nil {
		logger.LogError("failed to unmarshal policy rules", logger.ErrorField(err), logger.String("id", id))
		p.Rules = map[string]interface{}{"error": "invalid rules json"}
	}
	return p, nil
}

func (s *PostgresAdminStore) CreatePolicy(policy *Policy) error {
	const q = `INSERT INTO policies (id, name, type, target_id, rules, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`
	rulesJSON, _ := json.Marshal(policy.Rules)
	_, err := s.DB.Exec(context.Background(), q, policy.ID, policy.Name, policy.Type, policy.TargetID, string(rulesJSON))
	if err != nil {
		logger.LogError("failed to create policy", logger.ErrorField(err), logger.String("id", policy.ID))
		return errors.New("failed to create policy: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdatePolicy(policy *Policy) error {
	const q = `UPDATE policies SET name=$2, type=$3, target_id=$4, rules=$5, updated_at=NOW() WHERE id=$1`
	rulesJSON, _ := json.Marshal(policy.Rules)
	_, err := s.DB.Exec(context.Background(), q, policy.ID, policy.Name, policy.Type, policy.TargetID, string(rulesJSON))
	if err != nil {
		logger.LogError("failed to update policy", logger.ErrorField(err), logger.String("id", policy.ID))
		return errors.New("failed to update policy: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) DeletePolicy(id string) error {
	const q = `DELETE FROM policies WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	if err != nil {
		logger.LogError("failed to delete policy", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete policy: " + err.Error())
	}
	return nil
}

// SearchAuditLogs returns filtered, paginated audit logs and total count
func (s *PostgresAdminStore) SearchAuditLogs(filter AuditLogFilter) ([]interface{}, int, error) {
	ctx := context.Background()
	q := `SELECT id, actor_id, action, resource, details, created_at, hash, prev_hash FROM audit_logs`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.ActorID != "" {
		where = append(where, "actor_id = $"+strconv.Itoa(arg))
		args = append(args, filter.ActorID)
		arg++
	}
	if filter.Action != "" {
		where = append(where, "action = $"+strconv.Itoa(arg))
		args = append(args, filter.Action)
		arg++
	}
	if filter.Resource != "" {
		where = append(where, "resource = $"+strconv.Itoa(arg))
		args = append(args, filter.Resource)
		arg++
	}
	if filter.Start != nil {
		where = append(where, "created_at >= $"+strconv.Itoa(arg))
		args = append(args, *filter.Start)
		arg++
	}
	if filter.End != nil {
		where = append(where, "created_at <= $"+strconv.Itoa(arg))
		args = append(args, *filter.End)
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	qCount := "SELECT COUNT(*) FROM audit_logs"
	if len(where) > 0 {
		qCount += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC"
	limit := 100
	if filter.Limit > 0 && filter.Limit <= 1000 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}
	q += " LIMIT $" + strconv.Itoa(arg)
	args = append(args, limit)
	arg++
	q += " OFFSET $" + strconv.Itoa(arg)
	args = append(args, offset)
	// Query logs
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query audit logs", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query audit logs: " + err.Error())
	}
	defer rows.Close()
	logs := []interface{}{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt, hash, prevHash string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt, &hash, &prevHash); err != nil {
			logger.LogError("failed to scan audit log row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan audit log row: " + err.Error())
		}
		logs = append(logs, map[string]interface{}{
			"id":         id,
			"actor_id":   actorID,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"created_at": createdAt,
			"hash":       hash,
			"prev_hash":  prevHash,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating audit log rows", logger.ErrorField(err))
		return nil, 0, errors.New("error iterating audit log rows: " + err.Error())
	}
	// Query total count
	row := s.DB.QueryRow(ctx, qCount, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		logger.LogError("failed to get total audit log count", logger.ErrorField(err))
		total = 0 // fallback, not fatal
	}
	return logs, total, nil
}

// Implement SearchUsers
func (s *PostgresAdminStore) SearchUsers(filter UserFilter) ([]interface{}, int, error) {
	ctx := context.Background()
	q := `SELECT id, username, email, roles, created_at, updated_at FROM admin_users`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, "(username ILIKE $"+fmt.Sprint(arg)+" OR email ILIKE $"+fmt.Sprint(arg)+")")
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if filter.Role != "" {
		where = append(where, "$"+fmt.Sprint(arg)+" = ANY(roles)")
		args = append(args, filter.Role)
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "created_at DESC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "username" || col == "email" || col == "created_at" || col == "updated_at" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", arg, arg+1)
	args = append(args, filter.Limit, filter.Offset)
	// Count query
	countQ := "SELECT COUNT(*) FROM admin_users"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-1]...)
	var total int
	if err := row.Scan(&total); err != nil {
		logger.LogError("failed to count users", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count users: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query users", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query users: " + err.Error())
	}
	defer rows.Close()
	var users []interface{}
	for rows.Next() {
		var id, username, email string
		var roles []string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &username, &email, &roles, &createdAt, &updatedAt); err != nil {
			logger.LogError("failed to scan user row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan user row: " + err.Error())
		}
		users = append(users, map[string]interface{}{
			"id":         id,
			"username":   username,
			"email":      email,
			"roles":      roles,
			"created_at": createdAt.Format(time.RFC3339),
			"updated_at": updatedAt.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating user rows", logger.ErrorField(err))
		return nil, 0, errors.New("error iterating user rows: " + err.Error())
	}
	return users, total, nil
}

// Implement SearchTenants
func (s *PostgresAdminStore) SearchTenants(filter TenantFilter) ([]interface{}, int, error) {
	ctx := context.Background()
	q := `SELECT id, name, settings, created_at, updated_at FROM tenants`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, "name ILIKE $"+fmt.Sprint(arg))
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "created_at DESC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "name" || col == "created_at" || col == "updated_at" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", arg, arg+1)
	args = append(args, filter.Limit, filter.Offset)
	countQ := "SELECT COUNT(*) FROM tenants"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-1]...)
	var total int
	if err := row.Scan(&total); err != nil {
		logger.LogError("failed to count tenants", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count tenants: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query tenants", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query tenants: " + err.Error())
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var id, name, settings, createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &settings, &createdAt, &updatedAt); err != nil {
			logger.LogError("failed to scan tenant row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan tenant row: " + err.Error())
		}
		tenants = append(tenants, map[string]interface{}{
			"id":         id,
			"name":       name,
			"settings":   settings,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating tenant rows", logger.ErrorField(err))
		return nil, 0, errors.New("error iterating tenant rows: " + err.Error())
	}
	return tenants, total, nil
}

// Implement SearchRoles
func (s *PostgresAdminStore) SearchRoles(filter RoleFilter) ([]interface{}, int, error) {
	ctx := context.Background()
	q := `SELECT id, name, permissions FROM admin_roles`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, "name ILIKE $"+fmt.Sprint(arg))
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "name ASC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "name" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", arg, arg+1)
	args = append(args, filter.Limit, filter.Offset)
	countQ := "SELECT COUNT(*) FROM admin_roles"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-1]...)
	var total int
	if err := row.Scan(&total); err != nil {
		logger.LogError("failed to count roles", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count roles: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query roles", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query roles: " + err.Error())
	}
	defer rows.Close()
	var roles []interface{}
	for rows.Next() {
		var id, name string
		var permissions []string
		if err := rows.Scan(&id, &name, &permissions); err != nil {
			logger.LogError("failed to scan role row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan role row: " + err.Error())
		}
		roles = append(roles, map[string]interface{}{
			"id":          id,
			"name":        name,
			"permissions": permissions,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating role rows", logger.ErrorField(err))
		return nil, 0, errors.New("error iterating role rows: " + err.Error())
	}
	return roles, total, nil
}

// Implement SearchPermissions
func (s *PostgresAdminStore) SearchPermissions(filter PermissionFilter) ([]interface{}, int, error) {
	ctx := context.Background()
	q := `SELECT id, name FROM admin_permissions`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, "name ILIKE $"+fmt.Sprint(arg))
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "name ASC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "name" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", arg, arg+1)
	args = append(args, filter.Limit, filter.Offset)
	countQ := "SELECT COUNT(*) FROM admin_permissions"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-1]...)
	var total int
	if err := row.Scan(&total); err != nil {
		logger.LogError("failed to count permissions", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count permissions: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query permissions", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query permissions: " + err.Error())
	}
	defer rows.Close()
	var perms []interface{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			logger.LogError("failed to scan permission row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan permission row: " + err.Error())
		}
		perms = append(perms, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating permission rows", logger.ErrorField(err))
		return nil, 0, errors.New("error iterating permission rows: " + err.Error())
	}
	return perms, total, nil
}

// TraceUserActivity returns all audit logs for a given user (user trace)
func (s *PostgresAdminStore) TraceUserActivity(userID string) ([]interface{}, error) {
	if userID == "" {
		return nil, errors.New("user_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, actor_id, action, resource, details, created_at FROM audit_logs WHERE actor_id = $1 ORDER BY created_at DESC LIMIT 1000`
	rows, err := s.DB.Query(ctx, q, userID)
	if err != nil {
		logger.LogError("failed to query user trace logs", logger.ErrorField(err))
		return nil, errors.New("failed to query user trace logs: " + err.Error())
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			logger.LogError("failed to scan user trace log row", logger.ErrorField(err))
			return nil, errors.New("failed to scan user trace log row: " + err.Error())
		}
		logs = append(logs, map[string]interface{}{
			"id":         id,
			"actor_id":   actorID,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating user trace logs", logger.ErrorField(err))
		return nil, errors.New("error iterating user trace logs: " + err.Error())
	}
	return logs, nil
}

// TraceBillingActivity returns all audit logs for a given billing account (billing trace)
func (s *PostgresAdminStore) TraceBillingActivity(accountID string) ([]interface{}, error) {
	if accountID == "" {
		return nil, errors.New("account_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, actor_id, action, resource, details, created_at FROM audit_logs WHERE resource = 'billing' AND details LIKE $1 ORDER BY created_at DESC LIMIT 1000`
	pattern := "%account_id: '" + accountID + "'%"
	rows, err := s.DB.Query(ctx, q, pattern)
	if err != nil {
		logger.LogError("failed to query billing trace logs", logger.ErrorField(err))
		return nil, errors.New("failed to query billing trace logs: " + err.Error())
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			logger.LogError("failed to scan billing trace log row", logger.ErrorField(err))
			return nil, errors.New("failed to scan billing trace log row: " + err.Error())
		}
		logs = append(logs, map[string]interface{}{
			"id":         id,
			"actor_id":   actorID,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating billing trace logs", logger.ErrorField(err))
		return nil, errors.New("error iterating billing trace logs: " + err.Error())
	}
	return logs, nil
}

// ListImpersonationAudits returns impersonation audit logs (impersonation audit)
func (s *PostgresAdminStore) ListImpersonationAudits(limit, offset int) ([]interface{}, error) {
	ctx := context.Background()
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	const q = `SELECT id, actor_id, action, resource, details, created_at FROM audit_logs WHERE action = 'impersonate' ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	rows, err := s.DB.Query(ctx, q, limit, offset)
	if err != nil {
		logger.LogError("failed to query impersonation audit logs", logger.ErrorField(err))
		return nil, errors.New("failed to query impersonation audit logs: " + err.Error())
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			logger.LogError("failed to scan impersonation audit log row", logger.ErrorField(err))
			return nil, errors.New("failed to scan impersonation audit log row: " + err.Error())
		}
		logs = append(logs, map[string]interface{}{
			"id":         id,
			"actor_id":   actorID,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating impersonation audit logs", logger.ErrorField(err))
		return nil, errors.New("error iterating impersonation audit logs: " + err.Error())
	}
	return logs, nil
}

// GetRoleByID returns a role by its ID
func (s *PostgresAdminStore) GetRoleByID(id string) (*AdminRole, error) {
	if id == "" {
		return nil, errors.New("role id required")
	}
	ctx := context.Background()
	const q = `SELECT id, name, permissions FROM admin_roles WHERE id = $1`
	var role AdminRole
	if err := s.DB.QueryRow(ctx, q, id).Scan(&role.ID, &role.Name, &role.Permissions); err != nil {
		logger.LogError("role not found", logger.ErrorField(err))
		return nil, errors.New("role not found: " + err.Error())
	}
	return &role, nil
}

// ListAPIKeys returns filtered, paginated API keys and total count
func (s *PostgresAdminStore) ListAPIKeys(userID, status string, limit, offset int) ([]interface{}, int, error) {
	keys, total, err := s.listAPIKeysRaw(userID, status, limit, offset)
	if err != nil {
		logger.LogError("failed to list api keys", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list api keys: " + err.Error())
	}
	out := make([]interface{}, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out, total, nil
}

func (s *PostgresAdminStore) listAPIKeysRaw(userID, status string, limit, offset int) ([]APIKey, int, error) {
	ctx := context.Background()
	q := `SELECT id, user_id, name, status, created_at, updated_at, last_used_at FROM api_keys`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if userID != "" {
		where = append(where, "user_id = $"+strconv.Itoa(arg))
		args = append(args, userID)
		arg++
	}
	if status != "" {
		where = append(where, "status = $"+strconv.Itoa(arg))
		args = append(args, status)
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(arg) + " OFFSET $" + strconv.Itoa(arg+1)
	args = append(args, limit, offset)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query api keys", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query api keys: " + err.Error())
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		var k APIKey
		var userID sql.NullString
		var lastUsedAt sql.NullTime
		if err := rows.Scan(&k.ID, &userID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
			logger.LogError("failed to scan api key row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan api key row: " + err.Error())
		}
		k.UserID = userID.String
		if lastUsedAt.Valid {
			k.LastUsedAt = lastUsedAt.Time
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating api key rows", logger.ErrorField(err))
		return nil, 0, errors.New("error iterating api key rows: " + err.Error())
	}
	// Get total count
	countQ := `SELECT count(*) FROM api_keys`
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.DB.QueryRow(ctx, countQ, args[:arg-1]...).Scan(&total); err != nil {
		total = len(keys)
	}
	return keys, total, nil
}

func (s *PostgresAdminStore) CreateAPIKey(userID, name string) (interface{}, error) {
	k, err := s.createAPIKeyRaw(userID, name)
	if err != nil {
		logger.LogError("failed to create api key", logger.ErrorField(err))
		return nil, errors.New("failed to create api key: " + err.Error())
	}
	return k, nil
}

func (s *PostgresAdminStore) createAPIKeyRaw(userID, name string) (*APIKey, error) {
	ctx := context.Background()
	if userID == "" || name == "" {
		return nil, errors.New("user_id and name required")
	}
	id := uuid.NewString()
	key := generateAPIKey()
	now := time.Now().UTC()
	const q = `INSERT INTO api_keys (id, user_id, name, key, status, created_at, updated_at) VALUES ($1, $2, $3, $4, 'active', $5, $5)`
	_, err := s.DB.Exec(ctx, q, id, userID, name, key, now)
	if err != nil {
		logger.LogError("failed to create api key", logger.ErrorField(err))
		return nil, errors.New("failed to create api key: " + err.Error())
	}
	return &APIKey{
		ID:        id,
		UserID:    userID,
		Name:      name,
		Key:       key,
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (s *PostgresAdminStore) GetAPIKey(id string) (interface{}, error) {
	k, err := s.getAPIKeyRaw(id)
	if err != nil {
		logger.LogError("failed to get api key", logger.ErrorField(err))
		return nil, errors.New("failed to get api key: " + err.Error())
	}
	return k, nil
}

func (s *PostgresAdminStore) getAPIKeyRaw(id string) (*APIKey, error) {
	ctx := context.Background()
	if id == "" {
		return nil, errors.New("id required")
	}
	const q = `SELECT id, user_id, name, status, created_at, updated_at, last_used_at FROM api_keys WHERE id = $1`
	var k APIKey
	var userID sql.NullString
	var lastUsedAt sql.NullTime
	if err := s.DB.QueryRow(ctx, q, id).Scan(&k.ID, &userID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
		logger.LogError("api key not found", logger.ErrorField(err))
		return nil, errors.New("api key not found: " + err.Error())
	}
	k.UserID = userID.String
	if lastUsedAt.Valid {
		k.LastUsedAt = lastUsedAt.Time
	}
	return &k, nil
}

func (s *PostgresAdminStore) UpdateAPIKey(id, name string) (interface{}, error) {
	k, err := s.updateAPIKeyRaw(id, name)
	if err != nil {
		logger.LogError("failed to update api key", logger.ErrorField(err))
		return nil, errors.New("failed to update api key: " + err.Error())
	}
	return k, nil
}

func (s *PostgresAdminStore) updateAPIKeyRaw(id, name string) (*APIKey, error) {
	ctx := context.Background()
	if id == "" || name == "" {
		return nil, errors.New("id and name required")
	}
	const q = `UPDATE api_keys SET name = $2, updated_at = NOW() WHERE id = $1 RETURNING id, user_id, name, status, created_at, updated_at, last_used_at`
	var k APIKey
	var userID sql.NullString
	var lastUsedAt sql.NullTime
	if err := s.DB.QueryRow(ctx, q, id, name).Scan(&k.ID, &userID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
		logger.LogError("failed to update api key", logger.ErrorField(err))
		return nil, errors.New("failed to update api key: " + err.Error())
	}
	k.UserID = userID.String
	if lastUsedAt.Valid {
		k.LastUsedAt = lastUsedAt.Time
	}
	return &k, nil
}

func (s *PostgresAdminStore) RotateAPIKey(id string) (interface{}, error) {
	k, err := s.rotateAPIKeyRaw(id)
	if err != nil {
		logger.LogError("failed to rotate api key", logger.ErrorField(err))
		return nil, errors.New("failed to rotate api key: " + err.Error())
	}
	return k, nil
}

func (s *PostgresAdminStore) rotateAPIKeyRaw(id string) (*APIKey, error) {
	ctx := context.Background()
	if id == "" {
		return nil, errors.New("id required")
	}
	newKey := generateAPIKey()
	const q = `UPDATE api_keys SET key = $2, updated_at = NOW() WHERE id = $1 RETURNING id, user_id, name, status, created_at, updated_at, last_used_at`
	var k APIKey
	var userID sql.NullString
	var lastUsedAt sql.NullTime
	if err := s.DB.QueryRow(ctx, q, id, newKey).Scan(&k.ID, &userID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
		logger.LogError("failed to rotate api key", logger.ErrorField(err))
		return nil, errors.New("failed to rotate api key: " + err.Error())
	}
	k.Key = newKey
	k.UserID = userID.String
	if lastUsedAt.Valid {
		k.LastUsedAt = lastUsedAt.Time
	}
	return &k, nil
}

func (s *PostgresAdminStore) ListAPIKeyAuditLogs(apiKeyID, userID, action string, start, end *time.Time, limit, offset int) ([]interface{}, int, error) {
	logs, total, err := s.listAPIKeyAuditLogsRaw(apiKeyID, userID, action, start, end, limit, offset)
	if err != nil {
		logger.LogError("failed to list api key audit logs", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list api key audit logs: " + err.Error())
	}
	out := make([]interface{}, len(logs))
	for i, l := range logs {
		out[i] = l
	}
	return out, total, nil
}

func (s *PostgresAdminStore) listAPIKeyAuditLogsRaw(apiKeyID, userID, action string, start, end *time.Time, limit, offset int) ([]APIKeyAuditLog, int, error) {
	ctx := context.Background()
	q := `SELECT id, api_key_id, user_id, action, details, created_at FROM api_key_audit_logs`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if apiKeyID != "" {
		where = append(where, "api_key_id = $"+strconv.Itoa(arg))
		args = append(args, apiKeyID)
		arg++
	}
	if userID != "" {
		where = append(where, "user_id = $"+strconv.Itoa(arg))
		args = append(args, userID)
		arg++
	}
	if action != "" {
		where = append(where, "action = $"+strconv.Itoa(arg))
		args = append(args, action)
		arg++
	}
	if start != nil {
		where = append(where, "created_at >= $"+strconv.Itoa(arg))
		args = append(args, *start)
		arg++
	}
	if end != nil {
		where = append(where, "created_at <= $"+strconv.Itoa(arg))
		args = append(args, *end)
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(arg) + " OFFSET $" + strconv.Itoa(arg+1)
	args = append(args, limit, offset)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to query api key audit logs", logger.ErrorField(err))
		return nil, 0, errors.New("failed to query api key audit logs: " + err.Error())
	}
	defer rows.Close()
	var logs []APIKeyAuditLog
	for rows.Next() {
		var l APIKeyAuditLog
		if err := rows.Scan(&l.ID, &l.APIKeyID, &l.UserID, &l.Action, &l.Details, &l.CreatedAt); err != nil {
			logger.LogError("failed to scan api key audit log row", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan api key audit log row: " + err.Error())
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating api key audit log rows", logger.ErrorField(err))
		return nil, 0, errors.New("error iterating api key audit log rows: " + err.Error())
	}
	// Get total count
	countQ := `SELECT count(*) FROM api_key_audit_logs`
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.DB.QueryRow(ctx, countQ, args[:arg-1]...).Scan(&total); err != nil {
		total = len(logs)
	}
	return logs, total, nil
}

// generateAPIKey generates a secure random API key
func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		logger.LogError("failed to generate api key", logger.ErrorField(err))
		panic("failed to generate api key: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ListNotifications returns filtered, paginated notifications and total count
func (s *PostgresAdminStore) ListNotifications(recipient, nType, status string, limit, offset int) ([]interface{}, int, error) {
	notifStore := getNotificationStore(s)
	notifs, err := notifStore.List(context.Background(), recipient, nType, status, limit, offset)
	if err != nil {
		logger.LogError("failed to list notifications", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list notifications: " + err.Error())
	}
	out := make([]interface{}, len(notifs))
	for i, n := range notifStoreToAdmin(notifs) {
		out[i] = n
	}
	return out, len(out), nil
}

func (s *PostgresAdminStore) SendNotification(nType, recipient, subject, body string) (interface{}, error) {
	notifStore := getNotificationStore(s)
	n := &Notification{
		ID:        uuid.NewString(),
		Type:      nType,
		Recipient: recipient,
		Subject:   subject,
		Body:      body,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}
	if err := notifStore.Send(context.Background(), notifToEnterprise(n)); err != nil {
		logger.LogError("failed to send notification", logger.ErrorField(err))
		return nil, errors.New("failed to send notification: " + err.Error())
	}
	return n, nil
}

func (s *PostgresAdminStore) GetNotification(id string) (interface{}, error) {
	notifStore := getNotificationStore(s)
	n, err := notifStore.GetByID(context.Background(), id)
	if err != nil {
		logger.LogError("failed to get notification", logger.ErrorField(err))
		return nil, errors.New("failed to get notification: " + err.Error())
	}
	return notifFromEnterprise(n), nil
}

func (s *PostgresAdminStore) MarkNotificationSent(id string, sentAt time.Time) (interface{}, error) {
	notifStore := getNotificationStore(s)
	if err := notifStore.MarkSent(context.Background(), id, sentAt); err != nil {
		logger.LogError("failed to mark notification sent", logger.ErrorField(err))
		return nil, errors.New("failed to mark notification sent: " + err.Error())
	}
	n, err := notifStore.GetByID(context.Background(), id)
	if err != nil {
		logger.LogError("failed to get notification", logger.ErrorField(err))
		return nil, errors.New("failed to get notification: " + err.Error())
	}
	return notifFromEnterprise(n), nil
}

// getNotificationStore returns a PostgresNotificationStore using s.DB
func getNotificationStore(s *PostgresAdminStore) *notifications.PostgresNotificationStore {
	return notifications.NewPostgresNotificationStore(s.DB, nil)
}

// notifToEnterprise converts admin.Notification to enterprise/notifications.Notification
func notifToEnterprise(n *Notification) *notifications.Notification {
	return &notifications.Notification{
		ID:        n.ID,
		Type:      n.Type,
		Recipient: n.Recipient,
		Subject:   n.Subject,
		Body:      n.Body,
		Status:    n.Status,
		CreatedAt: n.CreatedAt,
		SentAt:    n.SentAt,
	}
}

// notifFromEnterprise converts enterprise/notifications.Notification to admin.Notification
func notifFromEnterprise(n *notifications.Notification) *Notification {
	if n == nil {
		logger.LogError("failed to convert notification from enterprise", logger.ErrorField(errors.New("notification is nil")))
		return nil
	}
	return &Notification{
		ID:        n.ID,
		Type:      n.Type,
		Recipient: n.Recipient,
		Subject:   n.Subject,
		Body:      n.Body,
		Status:    n.Status,
		CreatedAt: n.CreatedAt,
		SentAt:    n.SentAt,
	}
}

func notifStoreToAdmin(list []*notifications.Notification) []*Notification {
	out := make([]*Notification, len(list))
	for i, n := range list {
		out[i] = notifFromEnterprise(n)
	}
	return out
}

// GetRateLimitConfig returns current admin rate limit config and status
func (s *PostgresAdminStore) GetRateLimitConfig() (interface{}, error) {
	ctx := context.Background()
	const key = "admin_rate_limit_config"
	var raw string
	err := s.DB.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&raw)
	if err != nil && err.Error() != "no rows in result set" {
		logger.LogError("failed to fetch rate limit config", logger.ErrorField(err))
		return nil, errors.New("failed to fetch rate limit config: " + err.Error())
	}
	var cfg RateLimitConfig
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			logger.LogError("invalid rate limit config json", logger.ErrorField(err))
			return nil, errors.New("invalid rate limit config json: " + err.Error())
		}
	}
	// Fetch real-time usage/stats from rate_limits table
	const q = `SELECT endpoint, limit_per_minute, current_usage FROM rate_limits WHERE role = 'admin'`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("failed to query rate limits", logger.ErrorField(err))
		return nil, errors.New("failed to query rate limits: " + err.Error())
	}
	defer rows.Close()
	var stats []map[string]interface{}
	for rows.Next() {
		var endpoint string
		var limitPerMinute, currentUsage int
		if err := rows.Scan(&endpoint, &limitPerMinute, &currentUsage); err != nil {
			logger.LogError("failed to scan rate limit row", logger.ErrorField(err))
			return nil, errors.New("failed to scan rate limit row: " + err.Error())
		}
		stats = append(stats, map[string]interface{}{
			"endpoint":         endpoint,
			"limit_per_minute": limitPerMinute,
			"current_usage":    currentUsage,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating rate limit rows", logger.ErrorField(err))
		return nil, errors.New("error iterating rate limit rows: " + err.Error())
	}
	return map[string]interface{}{
		"config": &cfg,
		"stats":  stats,
	}, nil
}

// UpdateRateLimitConfig updates admin rate limit config in system_config
func (s *PostgresAdminStore) UpdateRateLimitConfig(input *RateLimitConfigInput) (interface{}, error) {
	ctx := context.Background()
	const key = "admin_rate_limit_config"
	b, err := json.Marshal(input)
	if err != nil {
		logger.LogError("failed to marshal rate limit config", logger.ErrorField(err))
		return nil, errors.New("failed to marshal rate limit config: " + err.Error())
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`, key, string(b))
	if err != nil {
		logger.LogError("failed to update rate limit config", logger.ErrorField(err))
		return nil, errors.New("failed to update rate limit config: " + err.Error())
	}
	var cfg RateLimitConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		logger.LogError("invalid rate limit config json", logger.ErrorField(err))
		return nil, errors.New("invalid rate limit config json: " + err.Error())
	}
	return &cfg, nil
}

// GetMaintenanceMode returns current maintenance mode status
func (s *PostgresAdminStore) GetMaintenanceMode() (interface{}, error) {
	ctx := context.Background()
	const key = "maintenance_mode"
	var raw string
	var updatedAt time.Time
	err := s.DB.QueryRow(ctx, `SELECT value, updated_at FROM system_config WHERE key = $1`, key).Scan(&raw, &updatedAt)
	if err != nil && err.Error() != "no rows in result set" {
		logger.LogError("failed to fetch maintenance mode status", logger.ErrorField(err))
		return nil, errors.New("failed to fetch maintenance mode status: " + err.Error())
	}
	var status MaintenanceModeStatus
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &status); err != nil {
			logger.LogError("invalid maintenance mode json", logger.ErrorField(err))
			return nil, errors.New("invalid maintenance mode json: " + err.Error())
		}
	}
	status.UpdatedAt = updatedAt
	return &status, nil
}

// SetMaintenanceMode updates maintenance mode status in system_config
func (s *PostgresAdminStore) SetMaintenanceMode(maintenance bool) (interface{}, error) {
	ctx := context.Background()
	const key = "maintenance_mode"
	status := MaintenanceModeStatus{
		Maintenance: maintenance,
		UpdatedAt:   time.Now().UTC(),
	}
	b, err := json.Marshal(status)
	if err != nil {
		logger.LogError("failed to marshal maintenance mode status", logger.ErrorField(err))
		return nil, errors.New("failed to marshal maintenance mode status: " + err.Error())
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = $3`, key, string(b), status.UpdatedAt)
	if err != nil {
		logger.LogError("failed to update maintenance mode status", logger.ErrorField(err))
		return nil, errors.New("failed to update maintenance mode status: " + err.Error())
	}
	return &status, nil
}

// GetMonitoringConfig returns current real-time monitoring config and status
func (s *PostgresAdminStore) GetMonitoringConfig() (interface{}, error) {
	ctx := context.Background()
	const key = "admin_monitoring_config"
	var raw string
	var updatedAt time.Time
	err := s.DB.QueryRow(ctx, `SELECT value, updated_at FROM system_config WHERE key = $1`, key).Scan(&raw, &updatedAt)
	if err != nil && err.Error() != "no rows in result set" {
		logger.LogError("failed to fetch monitoring config", logger.ErrorField(err))
		return nil, errors.New("failed to fetch monitoring config: " + err.Error())
	}
	var cfg MonitoringConfig
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			logger.LogError("invalid monitoring config json", logger.ErrorField(err))
			return nil, errors.New("invalid monitoring config json: " + err.Error())
		}
	}
	// Optionally, fetch status (last_event_at, event_count) from monitoring_events table
	row := s.DB.QueryRow(ctx, `SELECT MAX(created_at), COUNT(*) FROM monitoring_events WHERE created_at > NOW() - INTERVAL '1 hour'`)
	var lastEventAt time.Time
	var eventCount int
	_ = row.Scan(&lastEventAt, &eventCount)
	cfg.Status = &MonitoringStatus{LastEventAt: lastEventAt, EventCount: eventCount}
	return &cfg, nil
}

// UpdateMonitoringConfig updates real-time monitoring config in system_config
func (s *PostgresAdminStore) UpdateMonitoringConfig(input *MonitoringConfigInput) (interface{}, error) {
	ctx := context.Background()
	const key = "admin_monitoring_config"
	b, err := json.Marshal(input)
	if err != nil {
		logger.LogError("failed to marshal monitoring config", logger.ErrorField(err))
		return nil, errors.New("failed to marshal monitoring config: " + err.Error())
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`, key, string(b))
	if err != nil {
		logger.LogError("failed to update monitoring config", logger.ErrorField(err))
		return nil, errors.New("failed to update monitoring config: " + err.Error())
	}
	var cfg MonitoringConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		logger.LogError("invalid monitoring config json", logger.ErrorField(err))
		return nil, errors.New("invalid monitoring config json: " + err.Error())
	}
	return &cfg, nil
}

// ListFeatureFlags returns all feature flags
func (s *PostgresAdminStore) ListFeatureFlags() ([]interface{}, error) {
	ctx := context.Background()
	const q = `SELECT flag, enabled, updated_at FROM feature_flags`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("failed to query feature flags", logger.ErrorField(err))
		return nil, errors.New("failed to query feature flags: " + err.Error())
	}
	defer rows.Close()
	var flags []interface{}
	for rows.Next() {
		var f FeatureFlag
		if err := rows.Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
			logger.LogError("failed to scan feature flag row", logger.ErrorField(err))
			return nil, errors.New("failed to scan feature flag row: " + err.Error())
		}
		flags = append(flags, f)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating feature flag rows", logger.ErrorField(err))
		return nil, errors.New("error iterating feature flag rows: " + err.Error())
	}
	return flags, nil
}

// CreateFeatureFlag creates a new feature flag
func (s *PostgresAdminStore) CreateFeatureFlag(input *FeatureFlagInput) (interface{}, error) {
	ctx := context.Background()
	if input.Flag == "" {
		logger.LogError("flag required")
		return nil, errors.New("flag required")
	}
	const q = `INSERT INTO feature_flags (flag, enabled, updated_at) VALUES ($1, $2, NOW()) RETURNING flag, enabled, updated_at`
	var f FeatureFlag
	if err := s.DB.QueryRow(ctx, q, input.Flag, input.Enabled).Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
		logger.LogError("failed to create feature flag", logger.ErrorField(err))
		return nil, errors.New("failed to create feature flag: " + err.Error())
	}
	return &f, nil
}

// UpdateFeatureFlag updates a feature flag
func (s *PostgresAdminStore) UpdateFeatureFlag(input *FeatureFlagInput) (interface{}, error) {
	ctx := context.Background()
	if input.Flag == "" {
		logger.LogError("flag required")
		return nil, errors.New("flag required")
	}
	const q = `UPDATE feature_flags SET enabled = $2, updated_at = NOW() WHERE flag = $1 RETURNING flag, enabled, updated_at`
	var f FeatureFlag
	if err := s.DB.QueryRow(ctx, q, input.Flag, input.Enabled).Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
		logger.LogError("failed to update feature flag", logger.ErrorField(err))
		return nil, errors.New("failed to update feature flag: " + err.Error())
	}
	return &f, nil
}

// DeleteFeatureFlag deletes a feature flag
func (s *PostgresAdminStore) DeleteFeatureFlag(flag string) error {
	ctx := context.Background()
	if flag == "" {
		logger.LogError("flag required")
		return errors.New("flag required")
	}
	const q = `DELETE FROM feature_flags WHERE flag = $1`
	_, err := s.DB.Exec(ctx, q, flag)
	if err != nil {
		logger.LogError("failed to delete feature flag", logger.ErrorField(err))
		return errors.New("failed to delete feature flag: " + err.Error())
	}
	return nil
}

// Implement GetSecretsStatus to satisfy AdminStore interface
func (s *PostgresAdminStore) GetSecretsStatus() (interface{}, error) {
	return s.SecretsStatus()
}

// Implement ListAuditLogs to satisfy AdminStore interface
func (s *PostgresAdminStore) ListAuditLogs() ([]interface{}, error) {
	logs, _, err := s.SearchAuditLogs(AuditLogFilter{})
	return logs, err
}

// RevokeAPIKey sets status='revoked' for the given API key id
func (s *PostgresAdminStore) RevokeAPIKey(id string) error {
	if id == "" {
		logger.LogError("id required")
		return errors.New("id required")
	}
	ctx := context.Background()
	const q = `UPDATE api_keys SET status = 'revoked', updated_at = NOW() WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to revoke api key", logger.ErrorField(err))
		return errors.New("failed to revoke api key: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("api key not found", logger.String("id", id))
		return errors.New("api key not found")
	}
	return nil
}

// UpdateSecrets updates secret status or rotates secret in secrets_manager table
func (s *PostgresAdminStore) UpdateSecrets(input *SecretsUpdateInput) (interface{}, error) {
	if input == nil || input.KeyID == "" {
		logger.LogError("key_id required")
		return nil, errors.New("key_id required")
	}
	ctx := context.Background()
	var (
		q    string
		args []interface{}
	)
	if input.Rotate {
		q = `UPDATE secrets_manager SET last_rotated = NOW() WHERE key_id = $1 RETURNING key_id, status, last_rotated`
		args = []interface{}{input.KeyID}
	} else if input.NewSecret != "" {
		q = `UPDATE secrets_manager SET secret = $2, last_rotated = NOW() WHERE key_id = $1 RETURNING key_id, status, last_rotated`
		args = []interface{}{input.KeyID, input.NewSecret}
	} else {
		q = `SELECT key_id, status, last_rotated FROM secrets_manager WHERE key_id = $1`
		args = []interface{}{input.KeyID}
	}
	var keyID, status string
	var lastRotated time.Time
	err := s.DB.QueryRow(ctx, q, args...).Scan(&keyID, &status, &lastRotated)
	if err != nil {
		logger.LogError("failed to update secret", logger.ErrorField(err))
		return nil, errors.New("failed to update secret: " + err.Error())
	}
	return map[string]interface{}{
		"key_id":       keyID,
		"status":       status,
		"last_rotated": lastRotated,
	}, nil
}

func (s *PostgresAdminStore) GetByUsername(ctx context.Context, username string) (*AdminUser, error) {
	const q = `SELECT id, username, email, password_hash, roles, created_at, updated_at FROM admin_users WHERE username = $1`
	row := s.DB.QueryRow(ctx, q, username)
	var u AdminUser
	var roles []string
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &roles, &u.CreatedAt, &u.UpdatedAt); err != nil {
		logger.LogError("failed to get admin user by username", logger.ErrorField(err))
		return nil, errors.New("admin user not found: " + err.Error())
	}
	u.Roles = roles
	return &u, nil
}

func (s *PostgresAdminStore) GetByEmail(ctx context.Context, email string) (*AdminUser, error) {
	const q = `SELECT id, username, email, password_hash, roles, created_at, updated_at FROM admin_users WHERE email = $1`
	row := s.DB.QueryRow(ctx, q, email)
	var u AdminUser
	var roles []string
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &roles, &u.CreatedAt, &u.UpdatedAt); err != nil {
		logger.LogError("failed to get admin user by email", logger.ErrorField(err))
		return nil, errors.New("admin user not found: " + err.Error())
	}
	u.Roles = roles
	return &u, nil
}

func (s *PostgresAdminStore) GetByID(ctx context.Context, id string) (*AdminUser, error) {
	const q = `SELECT id, username, email, password_hash, roles, created_at, updated_at FROM admin_users WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var u AdminUser
	var roles []string
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &roles, &u.CreatedAt, &u.UpdatedAt); err != nil {
		logger.LogError("failed to get admin user by id",
			logger.ErrorField(err),
			logger.String("id", id))
		return nil, errors.New("admin user not found")
	}
	u.Roles = roles
	return &u, nil
}

func (s *PostgresAdminStore) CreateUser(user *AdminUser) error {
	return s.Create(context.Background(), user)
}

func (s *PostgresAdminStore) Delete(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("id required")
		return errors.New("id required")
	}
	const q = `DELETE FROM admin_users WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete admin user",
			logger.ErrorField(err),
			logger.String("id", id))
		return errors.New("failed to delete admin user: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("admin user not found for deletion",
			logger.String("id", id))
		return errors.New("admin user not found")
	}
	return nil
}

func (s *PostgresAdminStore) Update(ctx context.Context, u *AdminUser) error {
	if u == nil || u.ID == "" {
		logger.LogError("admin user and id required")
		return errors.New("admin user and id required")
	}
	const q = `UPDATE admin_users SET username = $1, email = $2, password_hash = $3, roles = $4, updated_at = $5 WHERE id = $6`
	res, err := s.DB.Exec(ctx, q, u.Username, u.Email, u.PasswordHash, u.Roles, u.UpdatedAt, u.ID)
	if err != nil {
		logger.LogError("failed to update admin user",
			logger.ErrorField(err),
			logger.String("id", u.ID),
			logger.String("username", u.Username))
		return errors.New("failed to update admin user: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("admin user not found for update",
			logger.String("id", u.ID),
			logger.String("username", u.Username))
		return errors.New("admin user not found")
	}
	return nil
}

func (s *PostgresAdminStore) CreateOrgAPIKey(orgID, name string) (interface{}, error) {
	if orgID == "" || name == "" {
		logger.LogError("org_id and name required")
		return nil, errors.New("org_id and name required")
	}
	ctx := context.Background()
	id := uuid.NewString()
	key := generateAPIKey()
	now := time.Now().UTC()
	const q = `INSERT INTO api_keys (id, org_id, name, key, status, created_at, updated_at) VALUES ($1, $2, $3, $4, 'active', $5, $5)`
	_, err := s.DB.Exec(ctx, q, id, orgID, name, key, now)
	if err != nil {
		logger.LogError("failed to create org api key", logger.ErrorField(err))
		return nil, errors.New("failed to create org api key: " + err.Error())
	}
	return &APIKey{
		ID:        id,
		UserID:    orgID, // For org keys, UserID field holds orgID for compatibility
		Name:      name,
		Key:       key,
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (s *PostgresAdminStore) CreateOrgTeam(ctx context.Context, team *OrgTeam) error {
	if team == nil {
		logger.LogError("org team required")
		return errors.New("org team required")
	}
	if team.ID == "" {
		team.ID = uuid.NewString()
	}
	if team.OrgID == "" || team.Name == "" {
		logger.LogError("org_id and name required")
		return errors.New("org_id and name required")
	}
	if team.CreatedAt.IsZero() {
		team.CreatedAt = time.Now().UTC()
	}
	if team.UpdatedAt.IsZero() {
		team.UpdatedAt = team.CreatedAt
	}
	if team.UserIDs == nil {
		team.UserIDs = []string{}
	}
	const q = `INSERT INTO org_teams (id, org_id, name, description, user_ids, settings, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.DB.Exec(ctx, q, team.ID, team.OrgID, team.Name, team.Description, pq.Array(team.UserIDs), team.Settings, team.CreatedAt, team.UpdatedAt)
	if err != nil {
		logger.LogError("failed to create org team", logger.ErrorField(err))
		return errors.New("failed to create org team")
	}
	return nil
}

func (s *PostgresAdminStore) CreateProject(ctx context.Context, p *Project) error {
	if p == nil {
		logger.LogError("project required")
		return errors.New("project required")
	}
	if p.ID == "" {
		p.ID = "prj-" + uuid.NewString()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	const q = `INSERT INTO projects (id, tenant_id, name, description, owner_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.DB.Exec(ctx, q, p.ID, p.TenantID, p.Name, p.Description, p.OwnerID, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		logger.LogError("failed to create project", logger.ErrorField(err))
		return errors.New("failed to create project: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) CreateProjectAPIKey(projectID, name string) (interface{}, error) {
	if projectID == "" || name == "" {
		logger.LogError("project_id and name required")
		return nil, errors.New("project_id and name required")
	}
	ctx := context.Background()
	id := uuid.NewString()
	key := generateAPIKey()
	now := time.Now().UTC()
	const q = `INSERT INTO api_keys (id, project_id, name, key, status, created_at, updated_at) VALUES ($1, $2, $3, $4, 'active', $5, $5)`
	_, err := s.DB.Exec(ctx, q, id, projectID, name, key, now)
	if err != nil {
		logger.LogError("failed to create project api key", logger.ErrorField(err))
		return nil, errors.New("failed to create project api key: " + err.Error())
	}
	return &APIKey{
		ID:        id,
		UserID:    projectID, // For project keys, UserID field holds projectID for compatibility
		Name:      name,
		Key:       key,
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (s *PostgresAdminStore) CreateSSMBlog(ctx context.Context, blog *SSMBlog) error {
	if blog == nil {
		logger.LogError("ssm blog required")
		return errors.New("ssm blog required")
	}
	if blog.ID == "" {
		blog.ID = "blog-" + uuid.NewString()
	}
	if blog.Title == "" || blog.AuthorID == "" || blog.Body == "" {
		logger.LogError("title, author_id, and body required")
		return errors.New("title, author_id, and body required")
	}
	if blog.CreatedAt.IsZero() {
		blog.CreatedAt = time.Now().UTC()
	}
	if blog.UpdatedAt.IsZero() {
		blog.UpdatedAt = blog.CreatedAt
	}
	const q = `INSERT INTO ssm_blogs (id, title, author_id, body, status, tags, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.DB.Exec(ctx, q, blog.ID, blog.Title, blog.AuthorID, blog.Body, blog.Status, blog.Tags, blog.CreatedAt, blog.UpdatedAt)
	if err != nil {
		logger.LogError("failed to create ssm blog", logger.ErrorField(err))
		return errors.New("failed to create ssm blog: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) CreateSSMNews(ctx context.Context, news *SSMNews) error {
	if news == nil {
		logger.LogError("ssm news required")
		return errors.New("ssm news required")
	}
	if news.ID == "" {
		news.ID = "news-" + uuid.NewString()
	}
	if news.Title == "" || news.AuthorID == "" || news.Body == "" {
		logger.LogError("title, author_id, and body required")
		return errors.New("title, author_id, and body required")
	}
	if news.CreatedAt.IsZero() {
		news.CreatedAt = time.Now().UTC()
	}
	if news.UpdatedAt.IsZero() {
		news.UpdatedAt = news.CreatedAt
	}
	const q = `INSERT INTO ssm_news (id, title, author_id, body, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.DB.Exec(ctx, q, news.ID, news.Title, news.AuthorID, news.Body, news.Status, news.CreatedAt, news.UpdatedAt)
	if err != nil {
		logger.LogError("failed to create ssm news", logger.ErrorField(err))
		return errors.New("failed to create ssm news: " + err.Error())
	}
	return nil
}
func (s *PostgresAdminStore) BulkAddUsersToOrg(ctx context.Context, orgID string, users []*UserOrgProjectRole) error {
	if orgID == "" || users == nil {
		logger.LogError("org_id and users required")
		return errors.New("org_id and users required")
	}
	const q = `INSERT INTO org_users (org_id, user_id, role, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())`
	for _, user := range users {
		_, err := s.DB.Exec(ctx, q, orgID, user.UserID, user.Role)
		if err != nil {
			logger.LogError("failed to add user to org", logger.ErrorField(err))
			return errors.New("failed to add user to org: " + err.Error())
		}
	}
	return nil
}

func (s *PostgresAdminStore) ListAllUserRolesPermissions(ctx context.Context) ([]*UserRolesPermissions, error) {
	const q = `SELECT id, user_id, org_id, project_id, role, permissions, created_at, updated_at FROM user_org_project_roles`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("failed to list all user roles/permissions", logger.ErrorField(err))
		return nil, errors.New("failed to list all user roles/permissions: " + err.Error())
	}
	defer rows.Close()
	var results []*UserRolesPermissions
	for rows.Next() {
		var result UserRolesPermissions
		if err := rows.Scan(&result.ID, &result.UserID, &result.OrgID, &result.ProjectID, &result.Role, &result.Permissions, &result.CreatedAt, &result.UpdatedAt); err != nil {
			logger.LogError("failed to scan user roles/permissions", logger.ErrorField(err))
			return nil, errors.New("failed to scan user roles/permissions: " + err.Error())
		}
		results = append(results, &result)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to iterate user roles/permissions", logger.ErrorField(err))
		return nil, errors.New("failed to iterate user roles/permissions: " + err.Error())
	}
	return results, nil
}
func (s *PostgresAdminStore) Login(ctx context.Context, username, password string) (*AdminUser, error) {
	const q = `SELECT id, username, email, password_hash FROM admin_users WHERE username = $1 AND password_hash = $2`
	row := s.DB.QueryRow(ctx, q, username, password)
	var user AdminUser
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash); err != nil {
		return nil, errors.New("failed to login: " + err.Error())
	}
	return &user, nil
}

func (s *PostgresAdminStore) DeleteOrg(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("org_id required")
		return errors.New("org_id required")
	}
	const q = `DELETE FROM orgs WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete org", logger.ErrorField(err))
		return errors.New("failed to delete org: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("org not found", logger.String("id", id))
		return errors.New("org not found")
	}
	return nil
}

func (s *PostgresAdminStore) DeleteOrgTeam(ctx context.Context, orgID, teamID string) error {
	if orgID == "" || teamID == "" {
		logger.LogError("org_id and team_id required")
		return errors.New("org_id and team_id required")
	}
	const q = `DELETE FROM org_teams WHERE org_id = $1 AND id = $2`
	res, err := s.DB.Exec(ctx, q, orgID, teamID)
	if err != nil {
		logger.LogError("failed to delete org team", logger.ErrorField(err))
		return errors.New("failed to delete org team: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("org team not found", logger.String("org_id", orgID), logger.String("team_id", teamID))
		return errors.New("org team not found")
	}
	return nil
}

func (s *PostgresAdminStore) DeleteSSMBlog(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("blog id required")
		return errors.New("blog id required")
	}
	const q = `DELETE FROM ssm_blogs WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete ssm blog", logger.ErrorField(err))
		return errors.New("failed to delete ssm blog: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("ssm blog not found", logger.String("id", id))
		return errors.New("ssm blog not found")
	}
	return nil
}

func (s *PostgresAdminStore) DeleteSSMNews(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("news id required")
		return errors.New("news id required")
	}
	const q = `DELETE FROM ssm_news WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete ssm news", logger.ErrorField(err))
		return errors.New("failed to delete ssm news: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("ssm news not found", logger.String("id", id))
		return errors.New("ssm news not found")
	}
	return nil
}

func (s *PostgresAdminStore) GetOrg(ctx context.Context, id string) (*Organization, error) {
	if id == "" {
		logger.LogError("org_id required")
		return nil, errors.New("org_id required")
	}
	const q = `SELECT id, tenant_id, name, created_at, updated_at FROM orgs WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var org Organization
	if err := row.Scan(&org.ID, &org.TenantID, &org.Name, &org.CreatedAt, &org.UpdatedAt); err != nil {
		logger.LogError("org not found", logger.String("id", id))
		return nil, errors.New("org not found")
	}
	return &org, nil
}

func (s *PostgresAdminStore) GetOrgTeam(ctx context.Context, orgID, teamID string) (*OrgTeam, error) {
	if orgID == "" || teamID == "" {
		logger.LogError("org_id and team_id required")
		return nil, errors.New("org_id and team_id required")
	}
	const q = `SELECT id, org_id, name, description, user_ids, settings, created_at, updated_at FROM org_teams WHERE org_id = $1 AND id = $2`
	row := s.DB.QueryRow(ctx, q, orgID, teamID)
	var team OrgTeam
	var userIDs []string
	if err := row.Scan(&team.ID, &team.OrgID, &team.Name, &team.Description, &userIDs, &team.Settings, &team.CreatedAt, &team.UpdatedAt); err != nil {
		logger.LogError("org team not found", logger.String("org_id", orgID), logger.String("team_id", teamID))
		return nil, errors.New("org team not found")
	}
	team.UserIDs = userIDs
	return &team, nil
}

func (s *PostgresAdminStore) GetOrgSettings(orgID string) (map[string]interface{}, error) {
	if orgID == "" {
		logger.LogError("org_id required")
		return nil, errors.New("org_id required")
	}
	ctx := context.Background()
	const q = `SELECT settings FROM orgs WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, orgID)
	var settings map[string]interface{}
	if err := row.Scan(&settings); err != nil {
		logger.LogError("org settings not found", logger.String("org_id", orgID))
		return nil, errors.New("org settings not found")
	}
	return settings, nil
}

func (s *PostgresAdminStore) GetProject(ctx context.Context, id string) (*Project, error) {
	if id == "" {
		logger.LogError("project_id required")
		return nil, errors.New("project_id required")
	}
	const q = `SELECT id, tenant_id, name, description, owner_id, created_at, updated_at FROM projects WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var project Project
	if err := row.Scan(&project.ID, &project.TenantID, &project.Name, &project.Description, &project.OwnerID, &project.CreatedAt, &project.UpdatedAt); err != nil {
		logger.LogError("project not found", logger.String("id", id))
		return nil, errors.New("project not found")
	}
	return &project, nil
}

func (s *PostgresAdminStore) GetProjectSettings(projectID string) (map[string]interface{}, error) {
	if projectID == "" {
		logger.LogError("project_id required")
		return nil, errors.New("project_id required")
	}
	ctx := context.Background()
	const q = `SELECT settings FROM projects WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, projectID)
	var settings map[string]interface{}
	if err := row.Scan(&settings); err != nil {
		logger.LogError("project settings not found", logger.String("project_id", projectID))
		return nil, errors.New("project settings not found")
	}
	return settings, nil
}

func (s *PostgresAdminStore) GetSSMBlog(ctx context.Context, id string) (*SSMBlog, error) {
	if id == "" {
		logger.LogError("blog id required")
		return nil, errors.New("blog id required")
	}
	const q = `SELECT id, title, author_id, body, status, tags, created_at, updated_at FROM ssm_blogs WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var blog SSMBlog
	if err := row.Scan(&blog.ID, &blog.Title, &blog.AuthorID, &blog.Body, &blog.Status, &blog.Tags, &blog.CreatedAt, &blog.UpdatedAt); err != nil {
		logger.LogError("ssm blog not found", logger.String("id", id))
		return nil, errors.New("ssm blog not found")
	}
	return &blog, nil
}

func (s *PostgresAdminStore) GetSSMNews(ctx context.Context, id string) (*SSMNews, error) {
	if id == "" {
		logger.LogError("news id required")
		return nil, errors.New("news id required")
	}
	const q = `SELECT id, title, author_id, body, status, created_at, updated_at FROM ssm_news WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var news SSMNews
	if err := row.Scan(&news.ID, &news.Title, &news.AuthorID, &news.Body, &news.Status, &news.CreatedAt, &news.UpdatedAt); err != nil {
		logger.LogError("ssm news not found", logger.String("id", id))
		return nil, errors.New("ssm news not found")
	}
	return &news, nil
}

func (s *PostgresAdminStore) InviteProjectUser(projectID, email, role string) (interface{}, error) {
	if projectID == "" || email == "" || role == "" {
		logger.LogError("project_id, email, and role required")
		return nil, errors.New("project_id, email, and role required")
	}
	ctx := context.Background()
	id := uuid.NewString()
	now := time.Now().UTC()
	const q = `INSERT INTO project_invitations (id, project_id, email, role, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.DB.Exec(ctx, q, id, projectID, email, role, now, now)
	if err != nil {
		logger.LogError("failed to invite project user", logger.ErrorField(err))
		return nil, errors.New("failed to invite project user: " + err.Error())
	}
	return &ProjectInvitation{
		ID:        id,
		ProjectID: projectID,
		Email:     email,
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (s *PostgresAdminStore) ListProjects(ctx context.Context, filter ProjectFilter) ([]*Project, int, error) {
	q := `SELECT id, tenant_id, name, description, owner_id, created_at, updated_at FROM projects`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, "(name ILIKE $"+strconv.Itoa(arg)+" OR description ILIKE $"+strconv.Itoa(arg)+")")
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "created_at DESC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "name" || col == "created_at" || col == "updated_at" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	limit := 100
	if filter.Limit > 0 && filter.Limit <= 1000 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}
	q += " LIMIT $" + strconv.Itoa(arg)
	args = append(args, limit)
	arg++
	q += " OFFSET $" + strconv.Itoa(arg)
	args = append(args, offset)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errors.New("failed to list projects")
	}
	defer rows.Close()
	var projects []*Project
	for rows.Next() {
		var project Project
		if err := rows.Scan(&project.ID, &project.TenantID, &project.Name, &project.Description, &project.OwnerID, &project.CreatedAt, &project.UpdatedAt); err != nil {
			logger.LogError("failed to scan project", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan project: " + err.Error())
		}
		projects = append(projects, &project)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.New("failed to list projects")
	}
	countQ := "SELECT COUNT(*) FROM projects"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		return nil, 0, errors.New("failed to count projects")
	}
	return projects, total, nil
}

func (s *PostgresAdminStore) ListProjectInvitations(projectID string) ([]interface{}, error) {
	if projectID == "" {
		logger.LogError("project_id required")
		return nil, errors.New("project_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, project_id, email, role, created_at, updated_at FROM project_invitations WHERE project_id = $1`
	rows, err := s.DB.Query(ctx, q, projectID)
	if err != nil {
		logger.LogError("failed to list project invitations", logger.ErrorField(err))
		return nil, errors.New("failed to list project invitations: " + err.Error())
	}
	defer rows.Close()
	var invitations []interface{}
	for rows.Next() {
		var invitation ProjectInvitation
		if err := rows.Scan(&invitation.ID, &invitation.ProjectID, &invitation.Email, &invitation.Role, &invitation.CreatedAt, &invitation.UpdatedAt); err != nil {
			logger.LogError("failed to scan project invitation", logger.ErrorField(err))
			return nil, errors.New("failed to scan project invitation: " + err.Error())
		}
		invitations = append(invitations, &invitation)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to list project invitations", logger.ErrorField(err))
		return nil, errors.New("failed to list project invitations: " + err.Error())
	}
	return invitations, nil
}

func (s *PostgresAdminStore) ListProjectAPIKeys(projectID string) ([]*APIKey, error) {
	if projectID == "" {
		logger.LogError("project_id required")
		return nil, errors.New("project_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, user_id, project_id, name, key, status, created_at, updated_at FROM api_keys WHERE project_id = $1`
	rows, err := s.DB.Query(ctx, q, projectID)
	if err != nil {
		logger.LogError("failed to list project api keys", logger.ErrorField(err))
		return nil, errors.New("failed to list project api keys: " + err.Error())
	}
	defer rows.Close()
	var apiKeys []*APIKey
	for rows.Next() {
		var apiKey APIKey
		var userID sql.NullString
		if err := rows.Scan(&apiKey.ID, &userID, &apiKey.ProjectID, &apiKey.Name, &apiKey.Key, &apiKey.Status, &apiKey.CreatedAt, &apiKey.UpdatedAt); err != nil {
			logger.LogError("failed to scan project api key", logger.ErrorField(err))
			return nil, errors.New("failed to scan project api key: " + err.Error())
		}
		apiKey.UserID = userID.String
		apiKeys = append(apiKeys, &apiKey)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to list project api keys", logger.ErrorField(err))
		return nil, errors.New("failed to list project api keys: " + err.Error())
	}
	return apiKeys, nil
}

func (s *PostgresAdminStore) ListOrgAPIKeys(orgID string) ([]*APIKey, error) {
	if orgID == "" {
		logger.LogError("org_id required")
		return nil, errors.New("org_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, user_id, org_id, name, key, status, created_at, updated_at FROM api_keys WHERE org_id = $1`
	rows, err := s.DB.Query(ctx, q, orgID)
	if err != nil {
		logger.LogError("failed to list org api keys", logger.ErrorField(err))
		return nil, errors.New("failed to list org api keys: " + err.Error())
	}
	defer rows.Close()
	var apiKeys []*APIKey
	for rows.Next() {
		var apiKey APIKey
		var userID sql.NullString
		if err := rows.Scan(&apiKey.ID, &userID, &apiKey.OrgID, &apiKey.Name, &apiKey.Key, &apiKey.Status, &apiKey.CreatedAt, &apiKey.UpdatedAt); err != nil {
			logger.LogError("failed to scan org api key", logger.ErrorField(err))
			return nil, errors.New("failed to scan org api key: " + err.Error())
		}
		apiKey.UserID = userID.String
		apiKeys = append(apiKeys, &apiKey)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to list org api keys", logger.ErrorField(err))
		return nil, errors.New("failed to list org api keys: " + err.Error())
	}
	return apiKeys, nil
}

func (s *PostgresAdminStore) ListOrgInvitations(orgID string) ([]interface{}, error) {
	if orgID == "" {
		logger.LogError("org_id required")
		return nil, errors.New("org_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, org_id, email, role, created_at, updated_at FROM org_invitations WHERE org_id = $1`
	rows, err := s.DB.Query(ctx, q, orgID)
	if err != nil {
		logger.LogError("failed to list org invitations", logger.ErrorField(err))
		return nil, errors.New("failed to list org invitations: " + err.Error())
	}
	defer rows.Close()
	var invitations []interface{}
	for rows.Next() {
		var invitation OrgInvitation
		if err := rows.Scan(&invitation.ID, &invitation.OrgID, &invitation.Email, &invitation.Role, &invitation.CreatedAt, &invitation.UpdatedAt); err != nil {
			logger.LogError("failed to scan org invitation", logger.ErrorField(err))
			return nil, errors.New("failed to scan org invitation: " + err.Error())
		}
		invitations = append(invitations, &invitation)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to list org invitations", logger.ErrorField(err))
		return nil, errors.New("failed to list org invitations: " + err.Error())
	}
	return invitations, nil
}

func (s *PostgresAdminStore) ListOrgTeams(ctx context.Context, filter OrgTeamFilter) ([]*OrgTeam, int, error) {
	q := `SELECT id, org_id, name, description, user_ids, settings, created_at, updated_at FROM org_teams`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.OrgID != "" {
		where = append(where, "org_id = $"+strconv.Itoa(arg))
		args = append(args, filter.OrgID)
		arg++
	}
	if filter.Query != "" {
		where = append(where, "(name ILIKE $"+strconv.Itoa(arg)+" OR description ILIKE $"+strconv.Itoa(arg)+")")
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "created_at DESC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "name" || col == "created_at" || col == "updated_at" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	limit := 100
	if filter.Limit > 0 && filter.Limit <= 1000 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}
	q += " LIMIT $" + strconv.Itoa(arg)
	args = append(args, limit)
	arg++
	q += " OFFSET $" + strconv.Itoa(arg)
	args = append(args, offset)
	// Count query
	countQ := "SELECT COUNT(*) FROM org_teams"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		return nil, 0, errors.New("failed to count org teams")
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to list org teams", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list org teams")
	}
	defer rows.Close()
	var teams []*OrgTeam
	for rows.Next() {
		var team OrgTeam
		var userIDs []string
		if err := rows.Scan(&team.ID, &team.OrgID, &team.Name, &team.Description, &userIDs, &team.Settings, &team.CreatedAt, &team.UpdatedAt); err != nil {
			logger.LogError("failed to scan org team", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan org team: " + err.Error())
		}
		team.UserIDs = userIDs
		teams = append(teams, &team)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to list org teams", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list org teams")
	}
	return teams, total, nil
}

func (s *PostgresAdminStore) InviteOrgUser(orgID, email, role string) (interface{}, error) {
	if orgID == "" || email == "" || role == "" {
		logger.LogError("org_id, email, and role required")
		return nil, errors.New("org_id, email, and role required")
	}
	ctx := context.Background()
	id := uuid.NewString()
	now := time.Now().UTC()
	const q = `INSERT INTO org_invitations (id, org_id, email, role, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.DB.Exec(ctx, q, id, orgID, email, role, now, now)
	if err != nil {
		logger.LogError("failed to invite org user", logger.ErrorField(err))
		return nil, errors.New("failed to invite org user: " + err.Error())
	}
	return &OrgInvitation{
		ID:        id,
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (s *PostgresAdminStore) ListSSMBlogs(ctx context.Context, filter SSMBlogFilter) ([]*SSMBlog, int, error) {
	q := `SELECT id, title, body, author_id, tags, status, created_at, updated_at FROM ssm_blogs`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, "(title ILIKE $"+strconv.Itoa(arg)+" OR body ILIKE $"+strconv.Itoa(arg)+")")
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if filter.Status != "" {
		where = append(where, "status = $"+strconv.Itoa(arg))
		args = append(args, filter.Status)
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "created_at DESC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "title" || col == "created_at" || col == "updated_at" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	limit := 100
	if filter.Limit > 0 && filter.Limit <= 1000 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}
	q += " LIMIT $" + strconv.Itoa(arg)
	args = append(args, limit)
	arg++
	q += " OFFSET $" + strconv.Itoa(arg)
	args = append(args, offset)
	// Count query
	countQ := "SELECT COUNT(*) FROM ssm_blogs"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		logger.LogError("failed to count ssm blogs", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count ssm blogs: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to list ssm blogs", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list ssm blogs: " + err.Error())
	}
	defer rows.Close()
	var blogs []*SSMBlog
	for rows.Next() {
		var blog SSMBlog
		if err := rows.Scan(&blog.ID, &blog.Title, &blog.Body, &blog.AuthorID, &blog.Tags, &blog.Status, &blog.CreatedAt, &blog.UpdatedAt); err != nil {
			logger.LogError("failed to scan ssm blog", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan ssm blog: " + err.Error())
		}
		blogs = append(blogs, &blog)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to list ssm blogs", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list ssm blogs: " + err.Error())
	}
	return blogs, total, nil
}

func (s *PostgresAdminStore) ListSSMNews(ctx context.Context, filter SSMNewsFilter) ([]*SSMNews, int, error) {
	q := `SELECT id, title, body, author_id, status, created_at, updated_at FROM ssm_news`
	where := []string{}
	args := []interface{}{}
	arg := 1
	if filter.Query != "" {
		where = append(where, "(title ILIKE $"+strconv.Itoa(arg)+" OR body ILIKE $"+strconv.Itoa(arg)+")")
		args = append(args, "%"+filter.Query+"%")
		arg++
	}
	if filter.Status != "" {
		where = append(where, "status = $"+strconv.Itoa(arg))
		args = append(args, filter.Status)
		arg++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	order := "created_at DESC"
	if filter.SortBy != "" {
		col := strings.ToLower(filter.SortBy)
		if col == "title" || col == "created_at" || col == "updated_at" {
			dir := "ASC"
			if filter.SortDir == "DESC" {
				dir = "DESC"
			}
			order = col + " " + dir
		}
	}
	q += " ORDER BY " + order
	limit := 100
	if filter.Limit > 0 && filter.Limit <= 1000 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}
	q += " LIMIT $" + strconv.Itoa(arg)
	args = append(args, limit)
	arg++
	q += " OFFSET $" + strconv.Itoa(arg)
	args = append(args, offset)
	// Count query
	countQ := "SELECT COUNT(*) FROM ssm_news"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
	}
	row := s.DB.QueryRow(ctx, countQ, args[:arg-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		logger.LogError("failed to count ssm news", logger.ErrorField(err))
		return nil, 0, errors.New("failed to count ssm news: " + err.Error())
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("failed to list ssm news", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list ssm news: " + err.Error())
	}
	defer rows.Close()
	var news []*SSMNews
	for rows.Next() {
		var n SSMNews
		if err := rows.Scan(&n.ID, &n.Title, &n.Body, &n.AuthorID, &n.Status, &n.CreatedAt, &n.UpdatedAt); err != nil {
			logger.LogError("failed to scan ssm news", logger.ErrorField(err))
			return nil, 0, errors.New("failed to scan ssm news: " + err.Error())
		}
		news = append(news, &n)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("failed to list ssm news", logger.ErrorField(err))
		return nil, 0, errors.New("failed to list ssm news: " + err.Error())
	}
	return news, total, nil
}

func (s *PostgresAdminStore) OrgAuditLogs(orgID string) ([]interface{}, error) {
	if orgID == "" {
		logger.LogError("org_id required")
		return nil, errors.New("org_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, actor_id, action, resource, details, created_at FROM audit_logs WHERE resource = 'org' AND details::text LIKE $1 ORDER BY created_at DESC LIMIT 1000`
	pattern := "%org_id: '" + orgID + "'%"
	rows, err := s.DB.Query(ctx, q, pattern)
	if err != nil {
		logger.LogError("failed to query org audit logs", logger.ErrorField(err))
		return nil, errors.New("failed to query org audit logs: " + err.Error())
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			logger.LogError("failed to scan org audit log row", logger.ErrorField(err))
			return nil, errors.New("failed to scan org audit log row: " + err.Error())
		}
		logs = append(logs, map[string]interface{}{
			"id":         id,
			"actor_id":   actorID,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating org audit logs", logger.ErrorField(err))
		return nil, errors.New("error iterating org audit logs: " + err.Error())
	}
	return logs, nil
}

func (s *PostgresAdminStore) ProjectAuditLogs(projectID string) ([]interface{}, error) {
	if projectID == "" {
		logger.LogError("project_id required")
		return nil, errors.New("project_id required")
	}
	ctx := context.Background()
	const q = `SELECT id, actor_id, action, resource, details, created_at FROM audit_logs WHERE resource = 'project' AND details LIKE $1 ORDER BY created_at DESC LIMIT 1000`
	pattern := "%project_id: '" + projectID + "'%"
	rows, err := s.DB.Query(ctx, q, pattern)
	if err != nil {
		logger.LogError("failed to query project audit logs", logger.ErrorField(err))
		return nil, errors.New("failed to query project audit logs: " + err.Error())
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			logger.LogError("failed to scan project audit log row", logger.ErrorField(err))
			return nil, errors.New("failed to scan project audit log row: " + err.Error())
		}
		logs = append(logs, map[string]interface{}{
			"id":         id,
			"actor_id":   actorID,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating project audit logs", logger.ErrorField(err))
		return nil, errors.New("error iterating project audit logs: " + err.Error())
	}
	return logs, nil
}

func (s *PostgresAdminStore) UpdateOrgSettings(orgID string, settings map[string]interface{}) (map[string]interface{}, error) {
	if orgID == "" {
		logger.LogError("org_id required")
		return nil, errors.New("org_id required")
	}
	if settings == nil {
		logger.LogError("settings required")
		return nil, errors.New("settings required")
	}
	ctx := context.Background()
	b, err := json.Marshal(settings)
	if err != nil {
		logger.LogError("failed to marshal settings", logger.ErrorField(err))
		return nil, errors.New("failed to marshal settings: " + err.Error())
	}
	const q = `UPDATE orgs SET settings = $2, updated_at = NOW() WHERE id = $1 RETURNING settings`
	var updated string
	if err := s.DB.QueryRow(ctx, q, orgID, string(b)).Scan(&updated); err != nil {
		logger.LogError("failed to update org settings", logger.ErrorField(err))
		return nil, errors.New("failed to update org settings: " + err.Error())
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(updated), &out); err != nil {
		logger.LogError("invalid org settings json", logger.ErrorField(err))
		return nil, errors.New("invalid org settings json: " + err.Error())
	}
	return out, nil
}

func (s *PostgresAdminStore) UpdateOrgTeam(ctx context.Context, team *OrgTeam) error {
	if team == nil || team.ID == "" || team.OrgID == "" {
		logger.LogError("org team, id, and org_id required", logger.Any("team", team))
		return errors.New("org team, id, and org_id required: input invalid")
	}
	const q = `UPDATE org_teams SET name = $1, description = $2, user_ids = $3, settings = $4, updated_at = NOW() WHERE id = $5 AND org_id = $6`
	res, err := s.DB.Exec(ctx, q, team.Name, team.Description, pq.Array(team.UserIDs), team.Settings, team.ID, team.OrgID)
	if err != nil {
		logger.LogError("failed to update org team", logger.ErrorField(err))
		return errors.New("failed to update org team: " + err.Error())
	}
	if res.RowsAffected() == 0 {
		logger.LogError("org team not found")
		return errors.New("org team not found")
	}
	return nil
}

func (s *PostgresAdminStore) DeleteProject(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("project_id required")
		return errors.New("project_id required")
	}
	const q = `DELETE FROM projects WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete project", logger.ErrorField(err))
		return errors.New("failed to delete project: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdateProjectSettings(projectID string, settings map[string]interface{}) (map[string]interface{}, error) {
	if projectID == "" {
		logger.LogError("project_id required")
		return nil, errors.New("project_id required")
	}
	if settings == nil {
		logger.LogError("settings required")
		return nil, errors.New("settings required")
	}
	ctx := context.Background()
	b, err := json.Marshal(settings)
	if err != nil {
		logger.LogError("failed to marshal settings", logger.ErrorField(err))
		return nil, errors.New("failed to marshal settings: " + err.Error())
	}
	const q = `UPDATE projects SET settings = $2, updated_at = NOW() WHERE id = $1 RETURNING settings`
	var updated string
	if err := s.DB.QueryRow(ctx, q, projectID, string(b)).Scan(&updated); err != nil {
		logger.LogError("failed to update project settings", logger.ErrorField(err))
		return nil, errors.New("failed to update project settings: " + err.Error())
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(updated), &out); err != nil {
		logger.LogError("invalid project settings json", logger.ErrorField(err))
		return nil, errors.New("invalid project settings json: " + err.Error())
	}
	return out, nil
}

func (s *PostgresAdminStore) CreateOrg(ctx context.Context, org *Organization) error {
	if org == nil || org.Name == "" {
		logger.LogError("organization and name required")
		return errors.New("organization and name required")
	}
	if org.ID == "" {
		org.ID = uuid.NewString()
	}
	const q = `INSERT INTO orgs (id, tenant_id, name, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())`
	_, err := s.DB.Exec(ctx, q, org.ID, org.TenantID, org.Name)
	if err != nil {
		logger.LogError("failed to create organization", logger.ErrorField(err))
		return errors.New("failed to create organization: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdateSSMBlog(ctx context.Context, blog *SSMBlog) error {
	if blog == nil || blog.ID == "" {
		logger.LogError("ssm blog and id required")
		return errors.New("ssm blog and id required")
	}
	const q = `UPDATE ssm_blogs SET title = $1, body = $2, author_id = $3, status = $4, tags = $5, updated_at = NOW() WHERE id = $6`
	_, err := s.DB.Exec(ctx, q, blog.Title, blog.Body, blog.AuthorID, blog.Status, blog.Tags, blog.ID)
	if err != nil {
		logger.LogError("failed to update ssm blog", logger.ErrorField(err))
		return errors.New("failed to update ssm blog: " + err.Error())
	}
	return nil
}

func (s *PostgresAdminStore) UpdateSSMNews(ctx context.Context, news *SSMNews) error {
	if news == nil || news.ID == "" {
		logger.LogError("ssm news and id required")
		return errors.New("ssm news and id required")
	}
	const q = `UPDATE ssm_news SET title = $1, body = $2, author_id = $3, status = $4, updated_at = NOW() WHERE id = $5`
	_, err := s.DB.Exec(ctx, q, news.Title, news.Body, news.AuthorID, news.Status, news.ID)
	if err != nil {
		logger.LogError("failed to update ssm news", logger.ErrorField(err))
		return errors.New("failed to update ssm news: " + err.Error())
	}
	return nil
}

// ListOrganizations returns a paginated, filterable list of organizations for admin endpoints.
func (s *PostgresAdminStore) ListOrganizations(ctx context.Context, filter OrganizationFilter) ([]*Organization, int, error) {
	var (
		where   []string
		args    []interface{}
		orderBy = "created_at DESC"
		argPos  = 1
	)
	if filter.Query != "" {
		where = append(where, "name ILIKE $"+strconv.Itoa(argPos))
		args = append(args, "%"+filter.Query+"%")
		argPos++
	}
	if filter.SortBy != "" {
		orderBy = filter.SortBy
		if filter.SortDir != "" {
			orderBy += " " + filter.SortDir
		}
	}
	limit := 100
	if filter.Limit > 0 && filter.Limit <= 1000 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}
	q := "SELECT id, name, created_at, updated_at FROM orgs " + whereSQL + " ORDER BY " + orderBy + " LIMIT $" + strconv.Itoa(argPos) + " OFFSET $" + strconv.Itoa(argPos+1)
	args = append(args, limit, offset)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logErr := err.Error()
		// Log the real error for debugging
		if loggerPkg, ok := any(s).(interface {
			LogError(msg string, fields ...interface{})
		}); ok {
			loggerPkg.LogError("ListOrganizations query error", logErr, q, args)
		} else {
			fmt.Println("ListOrganizations query error:", logErr, q, args)
		}
		return nil, 0, errors.New("failed to query organizations")
	}
	defer rows.Close()
	var orgs []*Organization
	for rows.Next() {
		var org Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.CreatedAt, &org.UpdatedAt); err != nil {
			logErr := err.Error()
			if loggerPkg, ok := any(s).(interface {
				LogError(msg string, fields ...interface{})
			}); ok {
				loggerPkg.LogError("ListOrganizations scan error", logErr)
			} else {
				fmt.Println("ListOrganizations scan error:", logErr)
			}
			return nil, 0, errors.New("failed to scan organization row")
		}
		orgs = append(orgs, &org)
	}
	if err := rows.Err(); err != nil {
		logErr := err.Error()
		if loggerPkg, ok := any(s).(interface {
			LogError(msg string, fields ...interface{})
		}); ok {
			loggerPkg.LogError("ListOrganizations rows error", logErr)
		} else {
			fmt.Println("ListOrganizations rows error:", logErr)
		}
		return nil, 0, errors.New("error iterating organization rows")
	}
	countQ := "SELECT COUNT(*) FROM orgs " + whereSQL
	countArgs := args[:argPos-1]
	countRow := s.DB.QueryRow(ctx, countQ, countArgs...)
	var total int
	if err := countRow.Scan(&total); err != nil {
		logErr := err.Error()
		if loggerPkg, ok := any(s).(interface {
			LogError(msg string, fields ...interface{})
		}); ok {
			loggerPkg.LogError("ListOrganizations count error", logErr)
		} else {
			fmt.Println("ListOrganizations count error:", logErr)
		}
		return nil, 0, errors.New("failed to count organizations")
	}
	return orgs, total, nil
}

func (s *PostgresAdminStore) SeedPermissions(perms []AdminPermission) error {
	if len(perms) == 0 {
		return nil
	}
	ctx := context.Background()
	const q = `INSERT INTO admin_permissions (id, name, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) ON CONFLICT (name) DO NOTHING`
	for _, perm := range perms {
		_, err := s.DB.Exec(ctx, q, perm.ID, perm.Name)
		if err != nil {
			logger.LogError("failed to seed permission", logger.ErrorField(err), logger.String("id", perm.ID), logger.String("name", perm.Name))
			return errors.New("failed to seed permission: " + err.Error())
		}
	}
	return nil
}

func (s *PostgresAdminStore) SeedRoles(roles []AdminRole) error {
	if len(roles) == 0 {
		return nil
	}
	ctx := context.Background()
	const q = `INSERT INTO admin_roles (id, name, permissions, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW()) ON CONFLICT (name) DO NOTHING`
	for _, role := range roles {
		_, err := s.DB.Exec(ctx, q, role.ID, role.Name, role.Permissions)
		if err != nil {
			logger.LogError("failed to seed role", logger.ErrorField(err), logger.String("id", role.ID), logger.String("name", role.Name))
			return errors.New("failed to seed role: " + err.Error())
		}
	}
	return nil
}
