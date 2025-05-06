package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"encoding/base64"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/enterprise/notifications"

)





func NewPostgresAdminStore(db *pgxpool.Pool) *PostgresAdminStore {
	return &PostgresAdminStore{DB: db}
}

func (s *PostgresAdminStore) ListUsers() ([]interface{}, error) {
	const q = `SELECT id, username, email, roles, created_at, updated_at FROM admin_users`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query admin users")
	}
	defer rows.Close()
	var users []interface{}
	for rows.Next() {
		var id, username, email string
		var roles []string
		var createdAt, updatedAt string
		if err := rows.Scan(&id, &username, &email, &roles, &createdAt, &updatedAt); err != nil {
			return nil, errors.New("failed to scan admin user row")
		}
		users = append(users, map[string]interface{}{
			"id":         id,
			"username":   username,
			"email":      email,
			"roles":      roles,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating admin user rows")
	}
	return users, nil
}

func (s *PostgresAdminStore) ListTenants() ([]interface{}, error) {
	const q = `SELECT id, name, settings, created_at, updated_at FROM tenants`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query tenants")
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var id, name, settings string
		var createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &settings, &createdAt, &updatedAt); err != nil {
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
		return nil, errors.New("error iterating tenant rows")
	}
	return tenants, nil
}

func (s *PostgresAdminStore) ListRoles() ([]interface{}, error) {
	const q = `SELECT id, name, permissions FROM admin_roles`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query admin roles")
	}
	defer rows.Close()
	var roles []interface{}
	for rows.Next() {
		var id, name string
		var permissions []string
		if err := rows.Scan(&id, &name, &permissions); err != nil {
			return nil, errors.New("failed to scan admin role row")
		}
		roles = append(roles, map[string]interface{}{
			"id":          id,
			"name":        name,
			"permissions": permissions,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating admin role rows")
	}
	return roles, nil
}

func (s *PostgresAdminStore) ListPermissions() ([]interface{}, error) {
	const q = `SELECT id, name FROM admin_permissions`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query admin permissions")
	}
	defer rows.Close()
	var perms []interface{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, errors.New("failed to scan admin permission row")
		}
		perms = append(perms, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := rows.Err(); err != nil {
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
		return nil, errors.New("failed to aggregate billing summary")
	}
	return map[string]interface{}{"total": total, "currency": currency}, nil
}

func (s *PostgresAdminStore) SystemHealth() (interface{}, error) {
	ctx := context.Background()
	// Check DB connection
	if err := s.DB.Ping(ctx); err != nil {
		return map[string]interface{}{"status": "unhealthy", "db": "down"}, nil
	}
	// Check critical table existence
	tables := []string{"admin_users", "tenants", "billing_records"}
	for _, tbl := range tables {
		q := "SELECT 1 FROM " + tbl + " LIMIT 1"
		if _, err := s.DB.Exec(ctx, q); err != nil {
			return map[string]interface{}{"status": "unhealthy", "db": "ok", "missing_table": tbl}, nil
		}
	}
	return map[string]interface{}{"status": "healthy", "db": "ok"}, nil
}

func (s *PostgresAdminStore) ListSessions() ([]interface{}, error) {
	const q = `SELECT id, user_id, created_at, expires_at, ip_address FROM admin_sessions WHERE expires_at > NOW()`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query admin sessions")
	}
	defer rows.Close()
	var sessions []interface{}
	for rows.Next() {
		var id, userID, ip string
		var createdAt, expiresAt string
		if err := rows.Scan(&id, &userID, &createdAt, &expiresAt, &ip); err != nil {
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
		return nil, errors.New("failed to create impersonation session")
	}
	// Log the impersonation event
	const logEvent = `INSERT INTO audit_logs (actor_id, action, resource, details, created_at, hash, prev_hash) VALUES ($1, 'impersonate', 'admin_sessions', $2, NOW(), '', '')`
	if _, err := s.DB.Exec(ctx, logEvent, userID, "Impersonation session created"); err != nil {
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
		return nil, errors.New("failed to query support tools")
	}
	defer rows.Close()
	var tools []map[string]interface{}
	for rows.Next() {
		var name, status string
		if err := rows.Scan(&name, &status); err != nil {
			return nil, errors.New("failed to scan support tool row")
		}
		tools = append(tools, map[string]interface{}{
			"name":   name,
			"status": status,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating support tool rows")
	}
	return map[string]interface{}{"tools": tools}, nil
}

func (s *PostgresAdminStore) RBACStatus() (interface{}, error) {
	const q = `SELECT value FROM system_config WHERE key = 'rbac_enabled'`
	row := s.DB.QueryRow(context.Background(), q)
	var value string
	if err := row.Scan(&value); err != nil {
		return nil, errors.New("failed to query RBAC status")
	}
	return map[string]interface{}{"rbac": value == "true"}, nil
}

func (s *PostgresAdminStore) StepUpAuth(userID string) (interface{}, error) {
	const q = `UPDATE admin_users SET stepup_required = TRUE WHERE id = $1 RETURNING id`
	row := s.DB.QueryRow(context.Background(), q, userID)
	var id string
	if err := row.Scan(&id); err != nil {
		return nil, errors.New("failed to mark user for step-up auth")
	}
	return map[string]interface{}{"user_id": id, "stepup": true}, nil
}

func (s *PostgresAdminStore) DelegatedAdminStatus() (interface{}, error) {
	const q = `SELECT value FROM system_config WHERE key = 'delegated_admin_enabled'`
	row := s.DB.QueryRow(context.Background(), q)
	var value string
	if err := row.Scan(&value); err != nil {
		return nil, errors.New("failed to query delegated admin status")
	}
	return map[string]interface{}{"delegated_admin": value == "true"}, nil
}

func (s *PostgresAdminStore) SCIMStatus() (interface{}, error) {
	const q = `SELECT value FROM system_config WHERE key = 'scim_enabled'`
	row := s.DB.QueryRow(context.Background(), q)
	var value string
	if err := row.Scan(&value); err != nil {
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
		return nil, errors.New("failed to query audit anomalies")
	}
	defer rows.Close()
	var anomalies []map[string]interface{}
	for rows.Next() {
		var id, actorID, action, resource, details string
		var createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
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
		return nil, errors.New("error iterating audit anomaly rows")
	}
	return map[string]interface{}{"anomalies": anomalies}, nil
}

func (s *PostgresAdminStore) RateLimits() (interface{}, error) {
	const q = `SELECT endpoint, limit_per_minute, current_usage FROM rate_limits WHERE role = 'admin'`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query rate limits")
	}
	defer rows.Close()
	var limits []map[string]interface{}
	for rows.Next() {
		var endpoint string
		var limitPerMinute, currentUsage int
		if err := rows.Scan(&endpoint, &limitPerMinute, &currentUsage); err != nil {
			return nil, errors.New("failed to scan rate limit row")
		}
		limits = append(limits, map[string]interface{}{
			"endpoint":         endpoint,
			"limit_per_minute": limitPerMinute,
			"current_usage":    currentUsage,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating rate limit rows")
	}
	return map[string]interface{}{"rate_limits": limits}, nil
}

func (s *PostgresAdminStore) AbuseDetection() (interface{}, error) {
	const q = `SELECT id, user_id, event_type, details, created_at FROM abuse_events WHERE created_at > NOW() - INTERVAL '24 hours'`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query abuse events")
	}
	defer rows.Close()
	var events []map[string]interface{}
	for rows.Next() {
		var id, userID, eventType, details string
		var createdAt string
		if err := rows.Scan(&id, &userID, &eventType, &details, &createdAt); err != nil {
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
		return nil, errors.New("error iterating abuse event rows")
	}
	return map[string]interface{}{"abuse_events": events, "abuse": len(events) > 0}, nil
}

func (s *PostgresAdminStore) Alerts() (interface{}, error) {
	const q = `SELECT id, type, message, severity, created_at FROM alerts WHERE active = TRUE`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query alerts")
	}
	defer rows.Close()
	var alerts []map[string]interface{}
	for rows.Next() {
		var id, alertType, message, severity, createdAt string
		if err := rows.Scan(&id, &alertType, &message, &severity, &createdAt); err != nil {
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
		return nil, errors.New("error iterating alert rows")
	}
	return map[string]interface{}{"alerts": alerts}, nil
}

func (s *PostgresAdminStore) SecretsStatus() (interface{}, error) {
	ctx := context.Background()
	const q = `SELECT key_id, status, last_rotated FROM secrets_manager WHERE active = TRUE`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		return nil, errors.New("failed to query secrets status")
	}
	defer rows.Close()
	var secrets []SecretInfo
	for rows.Next() {
		var keyID, status string
		var lastRotated time.Time
		if err := rows.Scan(&keyID, &status, &lastRotated); err != nil {
			return nil, errors.New("failed to scan secrets row")
		}
		secrets = append(secrets, SecretInfo{
			KeyID:       keyID,
			Status:      status,
			LastRotated: lastRotated,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating secrets rows")
	}
	return map[string]interface{}{"secrets": secrets}, nil
}

func (s *PostgresAdminStore) SystemConfig() (interface{}, error) {
	const q = `SELECT key, value, updated_at FROM system_config`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query system config")
	}
	defer rows.Close()
	var configs []map[string]interface{}
	for rows.Next() {
		var key, value, updatedAt string
		if err := rows.Scan(&key, &value, &updatedAt); err != nil {
			return nil, errors.New("failed to scan system config row")
		}
		configs = append(configs, map[string]interface{}{
			"key":        key,
			"value":      value,
			"updated_at": updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating system config rows")
	}
	return map[string]interface{}{"config": configs}, nil
}

func (s *PostgresAdminStore) FeatureFlags() ([]interface{}, error) {
	const q = `SELECT flag, enabled, updated_at FROM feature_flags`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query feature flags")
	}
	defer rows.Close()
	var flags []interface{}
	for rows.Next() {
		var f FeatureFlag
		if err := rows.Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
			return nil, errors.New("failed to scan feature flag row")
		}
		flags = append(flags, f)
	}
	if err := rows.Err(); err != nil {
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
		return nil, errors.New("failed to fetch maintenance mode status")
	}
	var status MaintenanceModeStatus
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &status); err != nil {
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
		return nil, errors.New("failed to query monitoring events")
	}
	defer rows.Close()
	var events []map[string]interface{}
	for rows.Next() {
		var id, eventType, message, createdAt string
		if err := rows.Scan(&id, &eventType, &message, &createdAt); err != nil {
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
		return nil, errors.New("error iterating monitoring event rows")
	}
	return map[string]interface{}{"monitoring": events}, nil
}

func (s *PostgresAdminStore) CreateUser(user *AdminUser) error {
	const q = `INSERT INTO admin_users (id, username, email, password_hash, roles, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`
	_, err := s.DB.Exec(context.Background(), q, user.ID, user.Username, user.Email, user.PasswordHash, user.Roles)
	return err
}

func (s *PostgresAdminStore) UpdateUser(user *AdminUser) error {
	const q = `UPDATE admin_users SET username=$2, email=$3, password_hash=$4, roles=$5, updated_at=NOW() WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, user.ID, user.Username, user.Email, user.PasswordHash, user.Roles)
	return err
}

func (s *PostgresAdminStore) DeleteUser(id string) error {
	const q = `DELETE FROM admin_users WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	return err
}

func (s *PostgresAdminStore) CreateTenant(tenant *Tenant) error {
	const q = `INSERT INTO tenants (id, name, settings, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())`
	_, err := s.DB.Exec(context.Background(), q, tenant.ID, tenant.Name, tenant.Settings)
	return err
}

func (s *PostgresAdminStore) UpdateTenant(tenant *Tenant) error {
	const q = `UPDATE tenants SET name=$2, settings=$3, updated_at=NOW() WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, tenant.ID, tenant.Name, tenant.Settings)
	return err
}

func (s *PostgresAdminStore) DeleteTenant(id string) error {
	const q = `DELETE FROM tenants WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	return err
}

func (s *PostgresAdminStore) CreateRole(role *AdminRole) error {
	const q = `INSERT INTO admin_roles (id, name, permissions) VALUES ($1, $2, $3)`
	_, err := s.DB.Exec(context.Background(), q, role.ID, role.Name, role.Permissions)
	return err
}

func (s *PostgresAdminStore) UpdateRole(role *AdminRole) error {
	const q = `UPDATE admin_roles SET name=$2, permissions=$3 WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, role.ID, role.Name, role.Permissions)
	return err
}

func (s *PostgresAdminStore) DeleteRole(id string) error {
	const q = `DELETE FROM admin_roles WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	return err
}

func (s *PostgresAdminStore) CreatePermission(perm *AdminPermission) error {
	const q = `INSERT INTO admin_permissions (id, name) VALUES ($1, $2)`
	_, err := s.DB.Exec(context.Background(), q, perm.ID, perm.Name)
	return err
}

func (s *PostgresAdminStore) UpdatePermission(perm *AdminPermission) error {
	const q = `UPDATE admin_permissions SET name=$2 WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, perm.ID, perm.Name)
	return err
}

func (s *PostgresAdminStore) DeletePermission(id string) error {
	const q = `DELETE FROM admin_permissions WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	return err
}

func (s *PostgresAdminStore) RevokeUserSessions(userID string) (int, error) {
	ctx := context.Background()
	if userID == "" {
		return 0, errors.New("user_id required")
	}
	count, err := s.SessionMgr.DeleteByUserID(ctx, userID)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *PostgresAdminStore) RevokeTenantSessions(tenantID string) (int, error) {
	ctx := context.Background()
	if tenantID == "" {
		return 0, errors.New("tenant_id required")
	}
	count, err := s.SessionMgr.DeleteByTenantID(ctx, tenantID)
	if err != nil {
		return 0, err
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
	return err
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
		return errors.New("user_id required")
	}
	const q = `UPDATE admin_users SET mfa_enabled = TRUE, mfa_reset_required = FALSE WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	return err
}

func (s *PostgresAdminStore) DisableMFA(userID string) error {
	ctx := context.Background()
	if userID == "" {
		return errors.New("user_id required")
	}
	const q = `UPDATE admin_users SET mfa_enabled = FALSE, mfa_secret = '', mfa_reset_required = FALSE WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	return err
}

func (s *PostgresAdminStore) ResetMFA(userID string) error {
	ctx := context.Background()
	if userID == "" {
		return errors.New("user_id required")
	}
	const q = `UPDATE admin_users SET mfa_secret = '', mfa_reset_required = TRUE WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, userID)
	return err
}

func (s *PostgresAdminStore) MFAStatus(userID string) (interface{}, error) {
	ctx := context.Background()
	if userID == "" {
		return nil, errors.New("user_id required")
	}
	const q = `SELECT mfa_enabled, mfa_reset_required FROM admin_users WHERE id = $1`
	var enabled bool
	var resetRequired bool
	err := s.DB.QueryRow(ctx, q, userID).Scan(&enabled, &resetRequired)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"mfa_enabled": enabled, "mfa_reset_required": resetRequired}, nil
}

func (s *PostgresAdminStore) ListPolicies() ([]interface{}, error) {
	const q = `SELECT id, name, type, target_id, rules, created_at, updated_at FROM policies`
	rows, err := s.DB.Query(context.Background(), q)
	if err != nil {
		return nil, errors.New("failed to query policies")
	}
	defer rows.Close()
	var policies []interface{}
	for rows.Next() {
		var p Policy
		var rulesJSON string
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.TargetID, &rulesJSON, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, errors.New("failed to scan policy row")
		}
		if err := json.Unmarshal([]byte(rulesJSON), &p.Rules); err != nil {
			p.Rules = map[string]interface{}{"error": "invalid rules json"}
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
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
		return nil, errors.New("policy not found")
	}
	if err := json.Unmarshal([]byte(rulesJSON), &p.Rules); err != nil {
		p.Rules = map[string]interface{}{"error": "invalid rules json"}
	}
	return p, nil
}

func (s *PostgresAdminStore) CreatePolicy(policy *Policy) error {
	const q = `INSERT INTO policies (id, name, type, target_id, rules, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`
	rulesJSON, _ := json.Marshal(policy.Rules)
	_, err := s.DB.Exec(context.Background(), q, policy.ID, policy.Name, policy.Type, policy.TargetID, string(rulesJSON))
	return err
}

func (s *PostgresAdminStore) UpdatePolicy(policy *Policy) error {
	const q = `UPDATE policies SET name=$2, type=$3, target_id=$4, rules=$5, updated_at=NOW() WHERE id=$1`
	rulesJSON, _ := json.Marshal(policy.Rules)
	_, err := s.DB.Exec(context.Background(), q, policy.ID, policy.Name, policy.Type, policy.TargetID, string(rulesJSON))
	return err
}

func (s *PostgresAdminStore) DeletePolicy(id string) error {
	const q = `DELETE FROM policies WHERE id=$1`
	_, err := s.DB.Exec(context.Background(), q, id)
	return err
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
		return nil, 0, errors.New("failed to query audit logs")
	}
	defer rows.Close()
	logs := []interface{}{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt, hash, prevHash string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt, &hash, &prevHash); err != nil {
			return nil, 0, errors.New("failed to scan audit log row")
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
		return nil, 0, errors.New("error iterating audit log rows")
	}
	// Query total count
	row := s.DB.QueryRow(ctx, qCount, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
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
		return nil, 0, errors.New("failed to count users")
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errors.New("failed to query users")
	}
	defer rows.Close()
	var users []interface{}
	for rows.Next() {
		var id, username, email string
		var roles []string
		var createdAt, updatedAt string
		if err := rows.Scan(&id, &username, &email, &roles, &createdAt, &updatedAt); err != nil {
			return nil, 0, errors.New("failed to scan user row")
		}
		users = append(users, map[string]interface{}{
			"id":         id,
			"username":   username,
			"email":      email,
			"roles":      roles,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.New("error iterating user rows")
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
		return nil, 0, errors.New("failed to count tenants")
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errors.New("failed to query tenants")
	}
	defer rows.Close()
	var tenants []interface{}
	for rows.Next() {
		var id, name, settings, createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &settings, &createdAt, &updatedAt); err != nil {
			return nil, 0, errors.New("failed to scan tenant row")
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
		return nil, 0, errors.New("error iterating tenant rows")
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
		return nil, 0, errors.New("failed to count roles")
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errors.New("failed to query roles")
	}
	defer rows.Close()
	var roles []interface{}
	for rows.Next() {
		var id, name string
		var permissions []string
		if err := rows.Scan(&id, &name, &permissions); err != nil {
			return nil, 0, errors.New("failed to scan role row")
		}
		roles = append(roles, map[string]interface{}{
			"id":          id,
			"name":        name,
			"permissions": permissions,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.New("error iterating role rows")
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
		return nil, 0, errors.New("failed to count permissions")
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errors.New("failed to query permissions")
	}
	defer rows.Close()
	var perms []interface{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, 0, errors.New("failed to scan permission row")
		}
		perms = append(perms, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.New("error iterating permission rows")
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
		return nil, errors.New("failed to query user trace logs")
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			return nil, errors.New("failed to scan user trace log row")
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
		return nil, errors.New("error iterating user trace logs")
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
		return nil, errors.New("failed to query billing trace logs")
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			return nil, errors.New("failed to scan billing trace log row")
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
		return nil, errors.New("error iterating billing trace logs")
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
		return nil, errors.New("failed to query impersonation audit logs")
	}
	defer rows.Close()
	var logs []interface{}
	for rows.Next() {
		var id, actorID, action, resource, details, createdAt string
		if err := rows.Scan(&id, &actorID, &action, &resource, &details, &createdAt); err != nil {
			return nil, errors.New("failed to scan impersonation audit log row")
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
		return nil, errors.New("error iterating impersonation audit logs")
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
		return nil, errors.New("role not found")
	}
	return &role, nil
}

// ListAPIKeys returns filtered, paginated API keys and total count
func (s *PostgresAdminStore) ListAPIKeys(userID, status string, limit, offset int) ([]interface{}, int, error) {
	keys, total, err := s.listAPIKeysRaw(userID, status, limit, offset)
	if err != nil {
		return nil, 0, err
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
		return nil, 0, errors.New("failed to query api keys")
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		var k APIKey
		var lastUsedAt sql.NullTime
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
			return nil, 0, errors.New("failed to scan api key row")
		}
		if lastUsedAt.Valid {
			k.LastUsedAt = lastUsedAt.Time
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.New("error iterating api key rows")
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
		return nil, err
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
		return nil, errors.New("failed to create api key")
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
		return nil, err
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
	var lastUsedAt sql.NullTime
	if err := s.DB.QueryRow(ctx, q, id).Scan(&k.ID, &k.UserID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
		return nil, errors.New("api key not found")
	}
	if lastUsedAt.Valid {
		k.LastUsedAt = lastUsedAt.Time
	}
	return &k, nil
}

func (s *PostgresAdminStore) UpdateAPIKey(id, name string) (interface{}, error) {
	k, err := s.updateAPIKeyRaw(id, name)
	if err != nil {
		return nil, err
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
	var lastUsedAt sql.NullTime
	if err := s.DB.QueryRow(ctx, q, id, name).Scan(&k.ID, &k.UserID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
		return nil, errors.New("failed to update api key")
	}
	if lastUsedAt.Valid {
		k.LastUsedAt = lastUsedAt.Time
	}
	return &k, nil
}

func (s *PostgresAdminStore) RotateAPIKey(id string) (interface{}, error) {
	k, err := s.rotateAPIKeyRaw(id)
	if err != nil {
		return nil, err
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
	var lastUsedAt sql.NullTime
	if err := s.DB.QueryRow(ctx, q, id, newKey).Scan(&k.ID, &k.UserID, &k.Name, &k.Status, &k.CreatedAt, &k.UpdatedAt, &lastUsedAt); err != nil {
		return nil, errors.New("failed to rotate api key")
	}
	k.Key = newKey
	if lastUsedAt.Valid {
		k.LastUsedAt = lastUsedAt.Time
	}
	return &k, nil
}

func (s *PostgresAdminStore) ListAPIKeyAuditLogs(apiKeyID, userID, action string, start, end *time.Time, limit, offset int) ([]interface{}, int, error) {
	logs, total, err := s.listAPIKeyAuditLogsRaw(apiKeyID, userID, action, start, end, limit, offset)
	if err != nil {
		return nil, 0, err
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
		return nil, 0, errors.New("failed to query api key audit logs")
	}
	defer rows.Close()
	var logs []APIKeyAuditLog
	for rows.Next() {
		var l APIKeyAuditLog
		if err := rows.Scan(&l.ID, &l.APIKeyID, &l.UserID, &l.Action, &l.Details, &l.CreatedAt); err != nil {
			return nil, 0, errors.New("failed to scan api key audit log row")
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errors.New("error iterating api key audit log rows")
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
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate api key")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ListNotifications returns filtered, paginated notifications and total count
func (s *PostgresAdminStore) ListNotifications(recipient, nType, status string, limit, offset int) ([]interface{}, int, error) {
	notifStore := getNotificationStore(s)
	notifs, err := notifStore.List(context.Background(), recipient, nType, status, limit, offset)
	if err != nil {
		return nil, 0, err
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
		return nil, err
	}
	return n, nil
}

func (s *PostgresAdminStore) GetNotification(id string) (interface{}, error) {
	notifStore := getNotificationStore(s)
	n, err := notifStore.GetByID(context.Background(), id)
	if err != nil {
		return nil, err
	}
	return notifFromEnterprise(n), nil
}

func (s *PostgresAdminStore) MarkNotificationSent(id string, sentAt time.Time) (interface{}, error) {
	notifStore := getNotificationStore(s)
	if err := notifStore.MarkSent(context.Background(), id, sentAt); err != nil {
		return nil, err
	}
	n, err := notifStore.GetByID(context.Background(), id)
	if err != nil {
		return nil, err
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
		return nil, errors.New("failed to fetch rate limit config")
	}
	var cfg RateLimitConfig
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return nil, errors.New("invalid rate limit config json")
		}
	}
	// Optionally, fetch current usage/status from rate limit store (not implemented here)
	return &cfg, nil
}

// UpdateRateLimitConfig updates admin rate limit config in system_config
func (s *PostgresAdminStore) UpdateRateLimitConfig(input *RateLimitConfigInput) (interface{}, error) {
	ctx := context.Background()
	const key = "admin_rate_limit_config"
	b, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("failed to marshal rate limit config")
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`, key, string(b))
	if err != nil {
		return nil, errors.New("failed to update rate limit config")
	}
	var cfg RateLimitConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, errors.New("invalid rate limit config json")
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
		return nil, errors.New("failed to fetch maintenance mode status")
	}
	var status MaintenanceModeStatus
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &status); err != nil {
			return nil, errors.New("invalid maintenance mode json")
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
		return nil, errors.New("failed to marshal maintenance mode status")
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = $3`, key, string(b), status.UpdatedAt)
	if err != nil {
		return nil, errors.New("failed to update maintenance mode status")
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
		return nil, errors.New("failed to fetch monitoring config")
	}
	var cfg MonitoringConfig
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return nil, errors.New("invalid monitoring config json")
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
		return nil, errors.New("failed to marshal monitoring config")
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`, key, string(b))
	if err != nil {
		return nil, errors.New("failed to update monitoring config")
	}
	var cfg MonitoringConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, errors.New("invalid monitoring config json")
	}
	return &cfg, nil
}

// ListFeatureFlags returns all feature flags
func (s *PostgresAdminStore) ListFeatureFlags() ([]interface{}, error) {
	ctx := context.Background()
	const q = `SELECT flag, enabled, updated_at FROM feature_flags`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		return nil, errors.New("failed to query feature flags")
	}
	defer rows.Close()
	var flags []interface{}
	for rows.Next() {
		var f FeatureFlag
		if err := rows.Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
			return nil, errors.New("failed to scan feature flag row")
		}
		flags = append(flags, f)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("error iterating feature flag rows")
	}
	return flags, nil
}

// CreateFeatureFlag creates a new feature flag
func (s *PostgresAdminStore) CreateFeatureFlag(input *FeatureFlagInput) (interface{}, error) {
	ctx := context.Background()
	if input.Flag == "" {
		return nil, errors.New("flag required")
	}
	const q = `INSERT INTO feature_flags (flag, enabled, updated_at) VALUES ($1, $2, NOW()) RETURNING flag, enabled, updated_at`
	var f FeatureFlag
	if err := s.DB.QueryRow(ctx, q, input.Flag, input.Enabled).Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
		return nil, errors.New("failed to create feature flag")
	}
	return &f, nil
}

// UpdateFeatureFlag updates a feature flag
func (s *PostgresAdminStore) UpdateFeatureFlag(input *FeatureFlagInput) (interface{}, error) {
	ctx := context.Background()
	if input.Flag == "" {
		return nil, errors.New("flag required")
	}
	const q = `UPDATE feature_flags SET enabled = $2, updated_at = NOW() WHERE flag = $1 RETURNING flag, enabled, updated_at`
	var f FeatureFlag
	if err := s.DB.QueryRow(ctx, q, input.Flag, input.Enabled).Scan(&f.Flag, &f.Enabled, &f.UpdatedAt); err != nil {
		return nil, errors.New("failed to update feature flag")
	}
	return &f, nil
}

// DeleteFeatureFlag deletes a feature flag
func (s *PostgresAdminStore) DeleteFeatureFlag(flag string) error {
	ctx := context.Background()
	if flag == "" {
		return errors.New("flag required")
	}
	const q = `DELETE FROM feature_flags WHERE flag = $1`
	_, err := s.DB.Exec(ctx, q, flag)
	return err
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
		return errors.New("id required")
	}
	ctx := context.Background()
	const q = `UPDATE api_keys SET status = 'revoked', updated_at = NOW() WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		return errors.New("failed to revoke api key")
	}
	if res.RowsAffected() == 0 {
		return errors.New("api key not found")
	}
	return nil
}

// UpdateSecrets updates secret status or rotates secret in secrets_manager table
func (s *PostgresAdminStore) UpdateSecrets(input *SecretsUpdateInput) (interface{}, error) {
	if input == nil || input.KeyID == "" {
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
		return nil, errors.New("failed to update secret")
	}
	return map[string]interface{}{
		"key_id":       keyID,
		"status":       status,
		"last_rotated": lastRotated,
	}, nil
}
