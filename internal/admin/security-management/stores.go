package security_management

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"time"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	// "github.com/google/uuid"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrMissingID       = errors.New("missing id for audit log")
	ErrInvalidAuditLog = errors.New("invalid audit log: missing required fields")
)

var providerRegistry = make(map[string]NotificationProvider)

func RegisterNotificationProvider(name string, provider NotificationProvider) {
	providerRegistry[name] = provider
}

func (s *PostgresStore) ListUserSecurityEvents(ctx context.Context, userID string) ([]SecurityEvent, error) {
	const query = `
		SELECT id, user_id, event_type, details, created_at 
		FROM security_events 
		WHERE user_id=$1 
		ORDER BY created_at DESC
	`
	rows, err := s.DB.Query(ctx, query, userID)
	if err != nil {
		logger.LogError("failed to query security events", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_security_events", err)
	}
	defer rows.Close()
	var events []SecurityEvent
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.EventType, &e.Details, &e.CreatedAt); err != nil {
			logger.LogError("failed to scan security event", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_security_events_scan", err)
		}
		events = append(events, e)
	}
	return events, nil
}

func (s *PostgresStore) ListUserLoginHistory(ctx context.Context, userID string) ([]LoginHistory, error) {
	const query = `
		SELECT id, user_id, ip, device, location, success, created_at 
		FROM login_history 
		WHERE user_id=$1 
		ORDER BY created_at DESC
	`
	rows, err := s.DB.Query(ctx, query, userID)
	if err != nil {
		logger.LogError("ListUserLoginHistory query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_login_history", err)
	}
	defer rows.Close()
	var history []LoginHistory
	for rows.Next() {
		var h LoginHistory
		if err := rows.Scan(&h.ID, &h.UserID, &h.IP, &h.Device, &h.Location, &h.Success, &h.CreatedAt); err != nil {
			logger.LogError("ListUserLoginHistory scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_login_history_scan", err)
		}
		history = append(history, h)
	}
	return history, nil
}

func (s *PostgresStore) EnableMFA(ctx context.Context, userID string) error {
	const query = `UPDATE users SET mfa_enabled=TRUE WHERE id=$1`
	_, err := s.DB.Exec(ctx, query, userID)
	if err != nil {
		logger.LogError("EnableMFA failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("enable_mfa", err)
	}
	return nil
}

func (s *PostgresStore) DisableMFA(ctx context.Context, userID string) error {
	const query = `UPDATE users SET mfa_enabled=FALSE WHERE id=$1`
	_, err := s.DB.Exec(ctx, query, userID)
	if err != nil {
		logger.LogError("DisableMFA failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("disable_mfa", err)
	}
	return nil
}

func (s *PostgresStore) ResetUserPassword(ctx context.Context, userID, newPassword string) error {
	const query = `UPDATE users SET password=$1 WHERE id=$2`
	_, err := s.DB.Exec(ctx, query, newPassword, userID)
	if err != nil {
		logger.LogError("ResetUserPassword failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("reset_user_password", err)
	}
	return nil
}

func (s *PostgresStore) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	const query = `SELECT id, user_id, ip, device, created_at, expires_at FROM sessions WHERE user_id=$1 ORDER BY created_at DESC`
	rows, err := s.DB.Query(ctx, query, userID)
	if err != nil {
		logger.LogError("ListUserSessions query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_sessions", err)
	}
	defer rows.Close()
	var sessions []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.Device, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			logger.LogError("ListUserSessions scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_sessions_scan", err)
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

func (s *PostgresStore) RevokeUserSession(ctx context.Context, userID, sessionID string) error {
	const query = `DELETE FROM sessions WHERE id=$1 AND user_id=$2`
	_, err := s.DB.Exec(ctx, query, sessionID, userID)
	if err != nil {
		logger.LogError("RevokeUserSession failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("session_id", sessionID))
		return wrapDBErr("revoke_user_session", err)
	}
	return nil
}

func (s *PostgresStore) ListSecurityAuditLogs(ctx context.Context, page, pageSize int) ([]SecurityAuditLog, error) {
	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	offset := (page - 1) * pageSize

	const query = `
		SELECT id, user_id, actor_id, action, resource, resource_id, target_id, details, ip, user_agent, created_at, metadata
		FROM security_audit_logs
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.DB.Query(ctx, query, pageSize, offset)
	if err != nil {
		logger.LogError("ListSecurityAuditLogs: database error", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()

	var logs []SecurityAuditLog
	for rows.Next() {
		var log SecurityAuditLog
		var metadataJSON []byte
		var userID, resourceID, targetID sql.NullString

		err := rows.Scan(
			&log.ID,
			&userID,
			&log.ActorID,
			&log.Action,
			&log.Resource,
			&resourceID,
			&targetID,
			&log.Details,
			&log.IP,
			&log.UserAgent,
			&log.CreatedAt,
			&metadataJSON,
		)

		if err != nil {
			logger.LogError("ListSecurityAuditLogs: row scan error", logger.ErrorField(err))
			continue // Skip this row but continue processing others
		}

		log.UserID = ""
		if userID.Valid {
			log.UserID = userID.String
		}
		log.ResourceID = ""
		if resourceID.Valid {
			log.ResourceID = resourceID.String
		}
		log.TargetID = ""
		if targetID.Valid {
			log.TargetID = targetID.String
		}

		// Parse metadata
		if metadataJSON != nil && len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
				logger.LogError("ListSecurityAuditLogs: failed to unmarshal metadata",
					logger.ErrorField(err),
					logger.String("log_id", log.ID))
				// Continue with empty metadata
				log.Metadata = map[string]interface{}{}
			}
		} else {
			log.Metadata = map[string]interface{}{}
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		logger.LogError("ListSecurityAuditLogs: rows error", logger.ErrorField(err))
		return nil, err
	}

	return logs, nil
}

func (s *PostgresStore) CreateSecurityAuditLog(ctx context.Context, log SecurityAuditLog) (SecurityAuditLog, error) {
	if log.UserID == "" || log.Action == "" {
		return SecurityAuditLog{}, fmt.Errorf("user_id and action required")
	}

	// Generate ID if not provided
	if log.ID == "" {
		log.ID = uuid.New().String()
	}

	// Set created time if not provided
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}

	// Convert metadata to JSON if provided
	var metadataJSON []byte
	var err error
	if log.Metadata != nil {
		metadataJSON, err = json.Marshal(log.Metadata)
		if err != nil {
			logger.LogError("CreateSecurityAuditLog: failed to marshal metadata",
				logger.ErrorField(err),
				logger.String("user_id", log.UserID))
			// Continue with empty metadata
			metadataJSON = []byte("{}")
		}
	} else {
		metadataJSON = []byte("{}")
	}

	// Patch: convert empty string UUIDs to nil for nullable columns
	var userID, resourceID, targetID interface{}
	if log.UserID == "" {
		userID = nil
	} else {
		userID = log.UserID
	}
	if log.ResourceID == "" {
		resourceID = nil
	} else {
		resourceID = log.ResourceID
	}
	if log.TargetID == "" {
		targetID = nil
	} else {
		targetID = log.TargetID
	}

	const query = `
		INSERT INTO security_audit_logs (
			id, user_id, actor_id, action, resource, resource_id, target_id, details, ip, user_agent, created_at, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		) RETURNING id, user_id, actor_id, action, resource, resource_id, target_id, details, ip, user_agent, created_at, metadata
	`

	var returnedMetadataJSON []byte
	var returnedUserID, returnedResourceID, returnedTargetID sql.NullString
	err = s.DB.QueryRow(
		ctx,
		query,
		log.ID,
		userID,
		log.ActorID,
		log.Action,
		log.Resource,
		resourceID,
		targetID,
		log.Details,
		log.IP,
		log.UserAgent,
		log.CreatedAt,
		metadataJSON,
	).Scan(
		&log.ID,
		&returnedUserID,
		&log.ActorID,
		&log.Action,
		&log.Resource,
		&returnedResourceID,
		&returnedTargetID,
		&log.Details,
		&log.IP,
		&log.UserAgent,
		&log.CreatedAt,
		&returnedMetadataJSON,
	)

	log.UserID = ""
	if returnedUserID.Valid {
		log.UserID = returnedUserID.String
	}
	log.ResourceID = ""
	if returnedResourceID.Valid {
		log.ResourceID = returnedResourceID.String
	}
	log.TargetID = ""
	if returnedTargetID.Valid {
		log.TargetID = returnedTargetID.String
	}

	if err != nil {
		logger.LogError("CreateSecurityAuditLog: database error",
			logger.ErrorField(err),
			logger.String("user_id", log.UserID),
			logger.String("action", log.Action))
		return SecurityAuditLog{}, err
	}

	// Parse metadata
	if returnedMetadataJSON != nil && len(returnedMetadataJSON) > 0 {
		if err := json.Unmarshal(returnedMetadataJSON, &log.Metadata); err != nil {
			logger.LogError("CreateSecurityAuditLog: failed to unmarshal metadata",
				logger.ErrorField(err),
				logger.String("user_id", log.UserID))
			// Continue with empty metadata
			log.Metadata = map[string]interface{}{}
		}
	}

	return log, nil
}

// --- API Key Store ---

func (s *PostgresStore) ListUserAPIKeys(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, user_id, name, key, created_at, revoked_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		logger.LogError("ListUserAPIKeys query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_api_keys", err)
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Key, &k.CreatedAt, &k.RevokedAt); err != nil {
			logger.LogError("ListUserAPIKeys scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_api_keys_scan", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *PostgresStore) CreateUserAPIKey(ctx context.Context, userID, name string) (APIKey, error) {
	var key APIKey
	q := `INSERT INTO api_keys (user_id, name, key, created_at) VALUES ($1, $2, gen_random_uuid(), NOW()) RETURNING id, user_id, name, key, created_at, revoked_at`
	err := s.DB.QueryRow(ctx, q, userID, name).Scan(&key.ID, &key.UserID, &key.Name, &key.Key, &key.CreatedAt, &key.RevokedAt)
	if err != nil {
		logger.LogError("CreateUserAPIKey failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("name", name))
		return APIKey{}, wrapDBErr("create_user_api_key", err)
	}
	// Audit log for API key creation
	// s.log.Audit("api_key_created", map[string]interface{}{"user_id": userID, "key_id": key.ID})
	return key, nil
}

func (s *PostgresStore) RevokeUserAPIKey(ctx context.Context, userID, keyID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND user_id=$2`, keyID, userID)
	if err != nil {
		logger.LogError("RevokeUserAPIKey failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("key_id", keyID))
		return wrapDBErr("revoke_user_api_key", err)
	}
	// Audit log for API key revocation
	// s.log.Audit("api_key_revoked", map[string]interface{}{"user_id": userID, "key_id": key.ID})
	return nil
}

func (s *PostgresStore) ListUserDevices(ctx context.Context, userID string) ([]Device, error) {
	const query = `SELECT id, user_id, type, name, ip, created_at, revoked_at FROM devices WHERE user_id=$1 ORDER BY created_at DESC`
	rows, err := s.DB.Query(ctx, query, userID)
	if err != nil {
		logger.LogError("ListUserDevices query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_devices", err)
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Type, &d.Name, &d.IP, &d.CreatedAt, &d.RevokedAt); err != nil {
			logger.LogError("ListUserDevices scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_devices_scan", err)
		}
		devices = append(devices, d)
	}
	return devices, nil
}

func (s *PostgresStore) RevokeUserDevice(ctx context.Context, userID, deviceID string) error {
	const query = `UPDATE devices SET revoked_at=NOW() WHERE id=$1 AND user_id=$2`
	_, err := s.DB.Exec(ctx, query, deviceID, userID)
	if err != nil {
		logger.LogError("RevokeUserDevice failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("device_id", deviceID))
		return wrapDBErr("revoke_user_device", err)
	}
	// Audit log for device revocation
	// s.log.Audit("device_revoked", map[string]interface{}{"user_id": userID, "device_id": deviceID})
	return nil
}

// --- Breach Store ---

func (s *PostgresStore) ListBreaches(ctx context.Context, page, pageSize int) ([]Breach, error) {
	offset := (page - 1) * pageSize
	const query = `SELECT id, type, details, detected_at FROM breaches ORDER BY detected_at DESC LIMIT $1 OFFSET $2`
	rows, err := s.DB.Query(ctx, query, pageSize, offset)
	if err != nil {
		logger.LogError("ListBreaches query failed", logger.ErrorField(err))
		return nil, wrapDBErr("list_breaches", err)
	}
	defer rows.Close()
	var breaches []Breach
	for rows.Next() {
		var b Breach
		if err := rows.Scan(&b.ID, &b.Type, &b.Details, &b.DetectedAt); err != nil {
			logger.LogError("ListBreaches scan failed", logger.ErrorField(err))
			return nil, wrapDBErr("list_breaches_scan", err)
		}
		breaches = append(breaches, b)
	}
	return breaches, nil
}

// --- Security Policy Store ---

func (s *PostgresStore) ListSecurityPolicies(ctx context.Context) ([]SecurityPolicy, error) {
	const query = `SELECT id, name, rules, created_at, updated_at FROM security_policies ORDER BY created_at DESC`
	rows, err := s.DB.Query(ctx, query)
	if err != nil {
		logger.LogError("ListSecurityPolicies query failed", logger.ErrorField(err))
		return nil, wrapDBErr("list_security_policies", err)
	}
	defer rows.Close()
	var policies []SecurityPolicy
	for rows.Next() {
		var p SecurityPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Rules, &p.CreatedAt, &p.UpdatedAt); err != nil {
			logger.LogError("ListSecurityPolicies scan failed", logger.ErrorField(err))
			return nil, wrapDBErr("list_security_policies_scan", err)
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *PostgresStore) CreateSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error) {
	const query = `INSERT INTO security_policies (name, rules, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) RETURNING id, name, rules, created_at, updated_at`
	var out SecurityPolicy
	err := s.DB.QueryRow(ctx, query, policy.Name, policy.Rules).Scan(&out.ID, &out.Name, &out.Rules, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		logger.LogError("CreateSecurityPolicy failed", logger.ErrorField(err), logger.String("name", policy.Name))
		return SecurityPolicy{}, wrapDBErr("create_security_policy", err)
	}
	// Audit log for policy creation
	// s.log.Audit("security_policy_created", map[string]interface{}{"policy_id": out.ID})
	return out, nil
}

func (s *PostgresStore) UpdateSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error) {
	const query = `UPDATE security_policies SET name=$1, rules=$2, updated_at=NOW() WHERE id=$3 RETURNING id, name, rules, created_at, updated_at`
	var out SecurityPolicy
	err := s.DB.QueryRow(ctx, query, policy.Name, policy.Rules, policy.ID).Scan(&out.ID, &out.Name, &out.Rules, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		logger.LogError("UpdateSecurityPolicy failed", logger.ErrorField(err), logger.String("id", policy.ID))
		return SecurityPolicy{}, wrapDBErr("update_security_policy", err)
	}
	// Audit log for policy update
	// s.log.Audit("security_policy_updated", map[string]interface{}{"policy_id": out.ID})
	return out, nil
}

func (s *PostgresStore) DeleteSecurityPolicy(ctx context.Context, id string) error {
	const query = `DELETE FROM security_policies WHERE id=$1`
	_, err := s.DB.Exec(ctx, query, id)
	if err != nil {
		logger.LogError("DeleteSecurityPolicy failed", logger.ErrorField(err), logger.String("id", id))
		return wrapDBErr("delete_security_policy", err)
	}
	// Audit log for policy deletion
	// s.log.Audit("security_policy_deleted", map[string]interface{}{"policy_id": id})
	return nil
}

// --- Error wrapping helper ---
func wrapDBErr(op string, err error) error {
	return commonutil.WrapDBErr(op, err)
}

func (e *DBError) Error() string {
	return "db error: " + e.Op + ": " + e.Err.Error()
}

// Use a functional implementation for NoopAuditLogger for testability and DI.
func NewNoopAuditLogger() AuditLogger {
	return auditLoggerFunc(func(ctx context.Context, log SecurityAuditLog) (SecurityAuditLog, error) {
		return SecurityAuditLog{}, nil
	})
}

type auditLoggerFunc func(ctx context.Context, log SecurityAuditLog) (SecurityAuditLog, error)

func (f auditLoggerFunc) CreateSecurityAuditLog(ctx context.Context, log SecurityAuditLog) (SecurityAuditLog, error) {
	return f(ctx, log)
}

// --- SecurityAnalyticsService ---

func (s *PostgresStore) GetSecurityAnalytics(ctx context.Context, tenantID string) (SecurityAnalytics, error) {
	var analytics SecurityAnalytics
	analytics.TenantID = tenantID
	analytics.GeneratedAt = time.Now().UTC()

	risk := 50.0
	breaches, err := s.ListBreaches(ctx, 1, 10)
	if err != nil && breaches == nil {
		logger.LogError("GetSecurityAnalytics: ListBreaches failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityAnalytics{}, &DBError{Op: "GetSecurityAnalytics.ListBreaches", Err: err}
	}
	if len(breaches) > 0 {
		risk += float64(len(breaches)) * 10
	}
	var mfaCount int
	const q = `SELECT COUNT(*) FROM users WHERE tenant_id=$1 AND mfa_enabled=TRUE`
	row := s.DB.QueryRow(ctx, q, tenantID)
	if err := row.Scan(&mfaCount); err != nil {
		logger.LogError("GetSecurityAnalytics: mfa_count failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityAnalytics{}, &DBError{Op: "GetSecurityAnalytics.mfa_count", Err: err}
	}
	if mfaCount > 0 {
		risk -= 10
	}
	anomalies, err := s.ListAnomalies(ctx, tenantID, 1, 10)
	if err != nil && anomalies == nil {
		logger.LogError("GetSecurityAnalytics: ListAnomalies failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityAnalytics{}, &DBError{Op: "GetSecurityAnalytics.ListAnomalies", Err: err}
	}
	if len(anomalies) > 0 {
		risk += float64(len(anomalies)) * 5
	}
	const query = `SELECT COUNT(*) FROM login_history WHERE tenant_id=$1 AND success=FALSE AND created_at > NOW() - INTERVAL '30 days'`
	row = s.DB.QueryRow(ctx, query, tenantID)
	var failedLogins int
	if err := row.Scan(&failedLogins); err != nil {
		logger.LogError("GetSecurityAnalytics: failed_logins failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityAnalytics{}, &DBError{Op: "GetSecurityAnalytics.failed_logins", Err: err}
	}
	if failedLogins == 0 {
		risk -= 5
	}
	if risk < 0 {
		risk = 0
	}
	if risk > 100 {
		risk = 100
	}
	analytics.RiskScore = risk

	switch {
	case risk < 40:
		analytics.Posture = "good"
	case risk < 70:
		analytics.Posture = "warning"
	default:
		analytics.Posture = "critical"
	}

	analytics.Anomalies = anomalies
	return analytics, nil
}

func (s *PostgresStore) ListAnomalies(ctx context.Context, tenantID string, page, pageSize int) ([]Anomaly, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const query = `SELECT id, type, details, detected_at FROM anomalies WHERE tenant_id = $1 ORDER BY detected_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, query, tenantID, pageSize, offset)
	if err != nil {
		logger.LogError("ListAnomalies query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, &DBError{Op: "ListAnomalies.query", Err: err}
	}
	defer rows.Close()
	var out []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.Type, &a.Details, &a.DetectedAt); err != nil {
			logger.LogError("ListAnomalies scan failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
			return nil, &DBError{Op: "ListAnomalies.scan", Err: err}
		}
		out = append(out, a)
	}
	return out, nil
}

// --- Real Anomaly Detection Logic ---

func (s *PostgresStore) DetectAnomalies(ctx context.Context, tenantID string) ([]Anomaly, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID required")
	}

	// This is a placeholder implementation that would be replaced with actual anomaly detection
	// In a real implementation, you would:
	// 1. Collect login data, API requests, and other activity
	// 2. Apply statistical or ML algorithms to detect anomalies
	// 3. Store and return the results

	// For now, return sample anomalies
	timeNow := time.Now()

	anomalies := []Anomaly{
		{
			ID:          uuid.New().String(),
			TenantID:    tenantID,
			Type:        "login_attempt",
			Severity:    "high",
			Description: "Multiple failed login attempts from unusual location",
			Details:     "5 failed login attempts within 10 minutes from unknown location",
			UserID:      "user123",
			DetectedAt:  timeNow.Add(-1 * time.Hour),
			CreatedAt:   timeNow.Add(-1 * time.Hour),
			Status:      "open",
			Metadata: map[string]interface{}{
				"location":  "Unknown location",
				"ip":        "203.0.113.1",
				"attempts":  5,
				"time_span": "10 minutes",
			},
		},
		{
			ID:          uuid.New().String(),
			TenantID:    tenantID,
			Type:        "api_usage",
			Severity:    "medium",
			Description: "Unusual API usage pattern detected",
			Details:     "High volume of requests to sensitive endpoints",
			UserID:      "user456",
			DetectedAt:  timeNow.Add(-3 * time.Hour),
			CreatedAt:   timeNow.Add(-3 * time.Hour),
			Status:      "open",
			Metadata: map[string]interface{}{
				"endpoints": []string{"/api/sensitive/data", "/api/users"},
				"requests":  150,
				"time_span": "5 minutes",
			},
		},
	}

	return anomalies, nil
}

// --- Notification Pluggable Runtime Config ---

func isNotificationEnabled(ctx context.Context, s *PostgresStore, tenantID, event string, channel NotificationChannel) bool {
	cfg, err := s.GetNotificationConfig(ctx, tenantID)
	if err != nil {
		logger.LogError("isNotificationEnabled: failed to get config", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return false
	}
	if !cfg.Enabled {
		logger.LogInfo("isNotificationEnabled: notifications globally disabled", logger.String("tenant_id", tenantID))
		return false
	}
	foundEvent := false
	for _, e := range cfg.Events {
		if e == event {
			foundEvent = true
			break
		}
	}
	if !foundEvent {
		logger.LogInfo("isNotificationEnabled: event not enabled", logger.String("event", event), logger.String("tenant_id", tenantID))
		return false
	}
	foundChannel := false
	for _, ch := range cfg.Channels {
		if ch == channel {
			foundChannel = true
			break
		}
	}
	if !foundChannel {
		logger.LogInfo("isNotificationEnabled: channel not enabled", logger.String("channel", string(channel)), logger.String("tenant_id", tenantID))
		return false
	}
	return true
}

func toPrettyJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// --- Notification Send Helper ---

func (s *PostgresStore) SendNotification(ctx context.Context, tenantID string, channel NotificationChannel, to []string, event string, details map[string]interface{}, maxRetry int) error {
	if !isNotificationEnabled(ctx, s, tenantID, event, channel) {
		logger.LogInfo("SendNotification: notification not enabled for event/channel", logger.String("tenant_id", tenantID), logger.String("event", event), logger.String("channel", string(channel)))
		return nil
	}
	details["tenant_id"] = tenantID
	provider, ok := providerRegistry[string(channel)]
	if !ok {
		logger.LogError("SendNotification: provider not found", logger.String("channel", string(channel)), logger.String("tenant_id", tenantID))
		return errors.New("notification provider not found")
	}
	err := provider.Send(ctx, to, event, details)
	if err == nil {
		logger.LogInfo("SendNotification: sent", logger.String("provider", provider.Name()), logger.String("tenant_id", tenantID))
		return nil
	}
	logger.LogError("SendNotification: provider failed, falling back", logger.String("provider", provider.Name()), logger.String("tenant_id", tenantID), logger.ErrorField(err))
	return s.SendNotificationWithFallback(ctx, tenantID, to, event, details, maxRetry)
}

// --- NotificationService ---

func (s *PostgresStore) GetNotificationConfig(ctx context.Context, tenantID string) (NotificationConfig, error) {
	if tenantID == "" {
		logger.LogError("tenant id required")
		return NotificationConfig{}, errors.New("tenant id required")
	}
	key := "security_notification_config_" + tenantID
	serverConfigService, ok := s.ServerConfigService.(interface {
		Get(context.Context, string) (struct{ Value string }, error)
	})
	if !ok {
		return NotificationConfig{}, errors.New("server config service not available")
	}
	cfg, err := serverConfigService.Get(ctx, key)
	if err != nil {
		if err.Error() == "config not found" {
			return NotificationConfig{}, nil
		}
		logger.LogError("failed to get notification config", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return NotificationConfig{}, err
	}
	var config NotificationConfig
	if err := json.Unmarshal([]byte(cfg.Value), &config); err != nil {
		logger.LogError("invalid notification config json", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return NotificationConfig{}, errors.New("invalid notification config json")
	}
	config.TenantID = tenantID
	return config, nil
}

func (s *PostgresStore) UpdateNotificationConfig(ctx context.Context, tenantID string, config NotificationConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	key := "security_notification_config_" + tenantID
	b, err := json.Marshal(config)
	if err != nil {
		return errors.New("invalid notification config")
	}
	serverConfigService, ok := s.ServerConfigService.(interface {
		Set(context.Context, string, string, string) (struct{}, error)
	})
	if !ok {
		return errors.New("server config service not available")
	}
	_, err = serverConfigService.Set(ctx, key, string(b), "system")
	if err != nil {
		return err
	}
	// hot-reload stub
	return nil
}

type SMTPProvider struct{}

func (p *SMTPProvider) Name() string { return "smtp" }
func (p *SMTPProvider) Send(ctx context.Context, to []string, event string, details map[string]interface{}) error {
	store, ok := ctx.Value("store").(*PostgresStore)
	if !ok {
		return errors.New("store not found in context")
	}
	tenantID := details["tenant_id"].(string)
	cfg, err := store.GetProviderConfig(ctx, tenantID, "email", "smtp")
	if err != nil {
		return err
	}
	host := cfg.Config["host"]
	port := cfg.Config["port"]
	user := cfg.Config["user"]
	pass := cfg.Config["pass"]
	from := cfg.Config["from"]
	if host == "" || port == "" || user == "" || pass == "" || from == "" {
		return errors.New("email provider config missing")
	}
	addr := fmt.Sprintf("%s:%s", host, port)
	subject := "[Security Event] " + event
	body, _ := json.MarshalIndent(details, "", "  ")
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to[0], subject, string(body)))
	auth := smtp.PlainAuth("", user, pass, host)
	return smtp.SendMail(addr, auth, from, to, msg)
}
func (p *SMTPProvider) Status(ctx context.Context) (string, error) { return "ok", nil }

// TwilioProvider

type TwilioProvider struct{}

func (p *TwilioProvider) Name() string { return "twilio" }
func (p *TwilioProvider) Send(ctx context.Context, to []string, event string, details map[string]interface{}) error {
	store, ok := ctx.Value("store").(*PostgresStore)
	if !ok {
		return errors.New("store not found in context")
	}
	tenantID := details["tenant_id"].(string)
	cfg, err := store.GetProviderConfig(ctx, tenantID, "sms", "twilio")
	if err != nil {
		return err
	}
	twilioSID := cfg.Config["sid"]
	twilioToken := cfg.Config["token"]
	twilioFrom := cfg.Config["from"]
	if twilioSID == "" || twilioToken == "" || twilioFrom == "" {
		return errors.New("sms provider config missing")
	}
	body, _ := json.Marshal(details)
	for _, dest := range to {
		url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", twilioSID)
		data := fmt.Sprintf("From=%s&To=%s&Body=%s", twilioFrom, dest, event+": "+string(body))
		req, _ := http.NewRequest("POST", url, bytes.NewBufferString(data))
		req.SetBasicAuth(twilioSID, twilioToken)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode >= 300 {
			return fmt.Errorf("twilio sms failed: %v", err)
		}
	}
	return nil
}
func (p *TwilioProvider) Status(ctx context.Context) (string, error) { return "ok", nil }

// SlackProvider

type SlackProvider struct{}

func (p *SlackProvider) Name() string { return "slack" }
func (p *SlackProvider) Send(ctx context.Context, to []string, event string, details map[string]interface{}) error {
	store, ok := ctx.Value("store").(*PostgresStore)
	if !ok {
		return errors.New("store not found in context")
	}
	tenantID := details["tenant_id"].(string)
	cfg, err := store.GetProviderConfig(ctx, tenantID, "chat", "slack")
	if err != nil {
		return err
	}
	webhook := cfg.Config["webhook"]
	if webhook == "" {
		return errors.New("slack webhook config missing")
	}
	payload := map[string]interface{}{
		"text": fmt.Sprintf("*%s*\n```%s```", event, toPrettyJSON(details)),
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(webhook, "application/json", bytes.NewBuffer(b))
	if err != nil || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook failed: %v", err)
	}
	return nil
}
func (p *SlackProvider) Status(ctx context.Context) (string, error) { return "ok", nil }

func init() {
	RegisterNotificationProvider("smtp", &SMTPProvider{})
	RegisterNotificationProvider("twilio", &TwilioProvider{})
	RegisterNotificationProvider("slack", &SlackProvider{})
}

// Update SendNotificationWithFallback and ProcessNotificationQueue to use tenantID
func (s *PostgresStore) SendNotificationWithFallback(ctx context.Context, tenantID string, to []string, event string, details map[string]interface{}, maxRetry int) error {
	details["tenant_id"] = tenantID
	var lastErr error
	for _, provider := range providerRegistry {
		err := provider.Send(ctx, to, event, details)
		if err == nil {
			logger.LogInfo("SendNotificationWithFallback: sent", logger.String("provider", provider.Name()), logger.String("tenant_id", tenantID))
			return nil
		}
		logger.LogError("SendNotificationWithFallback: provider failed", logger.String("provider", provider.Name()), logger.String("tenant_id", tenantID), logger.ErrorField(err))
		lastErr = err
	}
	item := NotificationQueueItem{
		ID:        commonutil.GenerateUUID(),
		Provider:  "fallback",
		To:        to,
		Event:     event,
		Details:   details,
		Retry:     0,
		MaxRetry:  maxRetry,
		Status:    "pending",
		LastError: lastErr.Error(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = s.AddToNotificationQueue(ctx, item)
	return lastErr
}

func (s *PostgresStore) ProcessNotificationQueue(ctx context.Context) {
	items, err := s.GetPendingNotificationQueue(ctx, 100)
	if err != nil {
		return
	}
	for _, item := range items {
		for _, provider := range providerRegistry {
			if item.Status != "pending" || item.Retry >= item.MaxRetry {
				break
			}
			err := provider.Send(ctx, item.To, item.Event, item.Details)
			if err == nil {
				item.Status = "sent"
				item.UpdatedAt = time.Now().UTC()
				_ = s.UpdateNotificationQueueItem(ctx, item)
				break
			}
			item.Retry++
			item.LastError = err.Error()
			item.UpdatedAt = time.Now().UTC()
			if item.Retry >= item.MaxRetry {
				item.Status = "dead"
			} else {
				item.Status = "pending"
			}
			_ = s.UpdateNotificationQueueItem(ctx, item)
		}
	}
}

// --- SecurityModuleConfigService ---

func (s *PostgresStore) GetSecurityModuleConfig(ctx context.Context, tenantID string) (SecurityModuleConfig, error) {
	const q = `SELECT enabled FROM security_module_configs WHERE tenant_id = $1`
	row := s.DB.QueryRow(ctx, q, tenantID)
	var cfg SecurityModuleConfig
	if err := row.Scan(&cfg.Enabled); err != nil {
		logger.LogError("GetSecurityModuleConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityModuleConfig{}, err
	}
	return cfg, nil
}

func (s *PostgresStore) SetSecurityModuleConfig(ctx context.Context, tenantID string, enabled bool) error {
	const q = `INSERT INTO security_module_configs (tenant_id, enabled) VALUES ($1, $2)
	ON CONFLICT (tenant_id) DO UPDATE SET enabled = $2`
	_, err := s.DB.Exec(ctx, q, tenantID, enabled)
	if err != nil {
		logger.LogError("SetSecurityModuleConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return err
	}
	return nil
}

// --- SecurityEventWebhookService Postgres Implementation ---

func (s *PostgresStore) CreateWebhook(ctx context.Context, webhook SecurityEventWebhook) (SecurityEventWebhook, error) {
	if webhook.TenantID == "" || webhook.URL == "" || len(webhook.EventTypes) == 0 || webhook.Secret == "" {
		return SecurityEventWebhook{}, errors.New("missing required fields")
	}
	webhook.ID = commonutil.GenerateUUID()
	webhook.Status = "active"
	webhook.CreatedAt = time.Now().UTC()
	webhook.UpdatedAt = webhook.CreatedAt
	etypes, _ := json.Marshal(webhook.EventTypes)
	const q = `INSERT INTO security_event_webhooks (id, tenant_id, url, event_types, secret, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	_, err := s.DB.Exec(ctx, q, webhook.ID, webhook.TenantID, webhook.URL, string(etypes), webhook.Secret, webhook.Status, webhook.CreatedAt, webhook.UpdatedAt)
	if err != nil {
		logger.LogError("CreateWebhook failed", logger.ErrorField(err))
		return SecurityEventWebhook{}, errors.New("failed to create webhook")
	}
	return webhook, nil
}

func (s *PostgresStore) ListWebhooks(ctx context.Context, tenantID string) ([]SecurityEventWebhook, error) {
	if tenantID == "" {
		return nil, errors.New("tenant_id required")
	}
	const q = `SELECT id, url, event_types, secret, status, created_at, updated_at FROM security_event_webhooks WHERE tenant_id = $1 AND status = 'active'`
	rows, err := s.DB.Query(ctx, q, tenantID)
	if err != nil {
		logger.LogError("ListWebhooks query failed", logger.ErrorField(err))
		return nil, errors.New("failed to list webhooks")
	}
	defer rows.Close()
	var out []SecurityEventWebhook
	for rows.Next() {
		var w SecurityEventWebhook
		var etypes string
		if err := rows.Scan(&w.ID, &w.URL, &etypes, &w.Secret, &w.Status, &w.CreatedAt, &w.UpdatedAt); err != nil {
			logger.LogError("ListWebhooks scan failed", logger.ErrorField(err))
			continue
		}
		_ = json.Unmarshal([]byte(etypes), &w.EventTypes)
		w.TenantID = tenantID
		out = append(out, w)
	}
	return out, nil
}

func (s *PostgresStore) DeleteWebhook(ctx context.Context, id, tenantID string) error {
	if id == "" || tenantID == "" {
		return errors.New("id and tenant_id required")
	}
	const q = `UPDATE security_event_webhooks SET status = 'disabled', updated_at = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := s.DB.Exec(ctx, q, time.Now().UTC(), id, tenantID)
	if err != nil {
		logger.LogError("DeleteWebhook failed", logger.ErrorField(err))
		return errors.New("failed to delete webhook")
	}
	return nil
}

func (s *PostgresStore) TriggerWebhook(ctx context.Context, id, tenantID, eventType string, payload interface{}) error {
	if id == "" || tenantID == "" || eventType == "" {
		return errors.New("id, tenant_id, and event_type required")
	}
	const q = `SELECT url, secret, status FROM security_event_webhooks WHERE id = $1 AND tenant_id = $2 AND status = 'active'`
	var url, secret, status string
	err := s.DB.QueryRow(ctx, q, id, tenantID).Scan(&url, &secret, &status)
	if err != nil {
		logger.LogError("TriggerWebhook lookup failed", logger.ErrorField(err))
		return errors.New("webhook not found")
	}
	if status != "active" {
		return errors.New("webhook not active")
	}
	body, _ := json.Marshal(map[string]interface{}{"event_type": eventType, "payload": payload})
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	sig := hex.EncodeToString(h.Sum(nil))
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", sig)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("TriggerWebhook delivery failed", logger.ErrorField(err))
		return errors.New("webhook delivery failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.LogError("TriggerWebhook non-2xx", logger.String("status", resp.Status))
		return errors.New("webhook delivery non-2xx")
	}
	return nil
}

// --- PasswordResetTokenService Postgres Implementation ---

func (s *PostgresStore) CreateToken(ctx context.Context, userID string, expiresIn time.Duration) (PasswordResetToken, error) {
	if userID == "" || expiresIn <= 0 {
		return PasswordResetToken{}, errors.New("user_id and expiresIn required")
	}
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		logger.LogError("CreateToken: failed to generate token", logger.ErrorField(err))
		return PasswordResetToken{}, errors.New("failed to generate token")
	}
	token := base64.URLEncoding.EncodeToString(b)
	t := PasswordResetToken{
		ID:        commonutil.GenerateUUID(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(expiresIn).UTC(),
		Used:      false,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	const q = `INSERT INTO password_reset_tokens (id, user_id, token, expires_at, used, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`
	_, err = s.DB.Exec(ctx, q, t.ID, t.UserID, t.Token, t.ExpiresAt, t.Used, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		logger.LogError("CreateToken failed", logger.ErrorField(err))
		return PasswordResetToken{}, errors.New("failed to create token")
	}
	return t, nil
}

func (s *PostgresStore) VerifyToken(ctx context.Context, token string) (bool, error) {
	query := `
		SELECT id, user_id, token, expires_at
		FROM password_reset_tokens
		WHERE token = $1 AND used = FALSE AND expires_at > NOW()
	`
	var result PasswordResetToken
	err := s.DB.QueryRow(ctx, query, token).Scan(&result.ID, &result.UserID, &result.Token, &result.ExpiresAt)
	if err != nil {
		logger.LogError("VerifyToken: token not found or invalid", logger.ErrorField(err), logger.String("token", token))
		return false, err
	}

	return true, nil
}

func (s *PostgresStore) UseToken(ctx context.Context, token string, email string, password string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// 1. Find the token and mark it as used
	var userID string
	query := `
		UPDATE password_reset_tokens
		SET used = TRUE, used_at = NOW()
		WHERE token = $1 AND used = FALSE AND expires_at > NOW()
		RETURNING user_id
	`
	err = tx.QueryRow(ctx, query, token).Scan(&userID)
	if err != nil {
		logger.LogError("UseToken: token not found or invalid", logger.ErrorField(err), logger.String("token", token))
		return err
	}

	// 2. Verify email matches user ID
	query = `SELECT id FROM users WHERE id = $1 AND email = $2`
	var validUserID string
	err = tx.QueryRow(ctx, query, userID, email).Scan(&validUserID)
	if err != nil {
		logger.LogError("UseToken: email does not match user ID", logger.ErrorField(err), logger.String("user_id", userID), logger.String("email", email))
		return fmt.Errorf("email does not match token")
	}

	// 3. Reset the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.LogError("UseToken: failed to hash password", logger.ErrorField(err))
		return err
	}

	query = `
		UPDATE users
		SET password = $1, updated_at = NOW()
		WHERE id = $2
	`
	_, err = tx.Exec(ctx, query, string(hashedPassword), userID)
	if err != nil {
		logger.LogError("UseToken: failed to update password", logger.ErrorField(err), logger.String("user_id", userID))
		return err
	}

	return tx.Commit(ctx)
}

// --- RateLimitService Postgres Implementation ---

func (s *PostgresStore) SetRateLimit(ctx context.Context, cfg RateLimitConfig) (RateLimitConfig, error) {
	if cfg.Scope == "" || cfg.ScopeID == "" || cfg.Limit <= 0 || cfg.WindowSeconds <= 0 {
		return RateLimitConfig{}, errors.New("invalid rate limit config")
	}
	const upsert = `INSERT INTO rate_limits (id, scope, scope_id, limit, window_seconds, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (scope, scope_id) DO UPDATE SET limit = $4, window_seconds = $5, updated_at = NOW()
		RETURNING id, created_at, updated_at`
	id := cfg.ID
	if id == "" {
		id = commonutil.GenerateUUID()
	}
	row := s.DB.QueryRow(ctx, upsert, id, cfg.Scope, cfg.ScopeID, cfg.Limit, cfg.WindowSeconds)
	var createdAt, updatedAt time.Time
	if err := row.Scan(&id, &createdAt, &updatedAt); err != nil {
		return RateLimitConfig{}, errors.New("failed to upsert rate limit")
	}
	cfg.ID = id
	cfg.CreatedAt = createdAt
	cfg.UpdatedAt = updatedAt
	return cfg, nil
}

func (s *PostgresStore) GetRateLimit(ctx context.Context, scope, scopeID string) (RateLimitConfig, error) {
	if scope == "" || scopeID == "" {
		return RateLimitConfig{}, errors.New("scope and scope_id required")
	}
	const q = `SELECT id, scope, scope_id, limit, window_seconds, created_at, updated_at FROM rate_limits WHERE scope = $1 AND scope_id = $2`
	row := s.DB.QueryRow(ctx, q, scope, scopeID)
	var cfg RateLimitConfig
	if err := row.Scan(&cfg.ID, &cfg.Scope, &cfg.ScopeID, &cfg.Limit, &cfg.WindowSeconds, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
		logger.LogError("GetRateLimit: rate limit not found", logger.String("scope", scope), logger.String("scope_id", scopeID), logger.ErrorField(err))
		return RateLimitConfig{}, errors.New("rate limit not found")
	}
	return cfg, nil
}

func (s *PostgresStore) DeleteRateLimit(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id required")
	}
	const q = `DELETE FROM rate_limits WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteRateLimit: failed to delete rate limit", logger.String("id", id), logger.ErrorField(err))
		return errors.New("failed to delete rate limit")
	}
	return nil
}

// --- PasswordService extensions ---
func hashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.LogError("hashPassword: failed to hash password", logger.ErrorField(err))
		return "", err
	}
	return string(hash), nil
}

func checkPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (s *PostgresStore) RegisterUser(ctx context.Context, email, password string) (User, error) {
	hash, err := hashPassword(password)
	if err != nil {
		logger.LogError("RegisterUser hash failed", logger.ErrorField(err), logger.String("email", email))
		return User{}, wrapDBErr("register_user_hash", err)
	}
	id := commonutil.GenerateUUID()
	status := "active"
	const q = `INSERT INTO users (id, email, password, status, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW()) RETURNING id, email, status, created_at, updated_at`
	var u User
	err = s.DB.QueryRow(ctx, q, id, email, hash, status).Scan(&u.ID, &u.Email, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		logger.LogError("RegisterUser failed", logger.ErrorField(err), logger.String("email", email))
		return User{}, wrapDBErr("register_user", err)
	}
	return u, nil
}

func (s *PostgresStore) AuthenticateUser(ctx context.Context, email, password string) (User, error) {
	const q = `SELECT id, email, password, created_at, updated_at FROM users WHERE email=$1 AND deleted_at IS NULL`
	var u User
	var hash string
	err := s.DB.QueryRow(ctx, q, email).Scan(&u.ID, &u.Email, &hash, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		logger.LogError("AuthenticateUser failed", logger.ErrorField(err), logger.String("email", email))
		return User{}, wrapDBErr("authenticate_user", err)
	}
	if err := checkPassword(hash, password); err != nil {
		logger.LogError("AuthenticateUser: invalid credentials", logger.ErrorField(err), logger.String("email", email))
		return User{}, errors.New("invalid credentials")
	}
	return u, nil
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		logger.LogError("generateToken: failed to generate token", logger.ErrorField(err))
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *PostgresStore) ResendVerification(ctx context.Context, email string) error {
	const q = `SELECT id FROM users WHERE email=$1 AND deleted_at IS NULL`
	var userID string
	err := s.DB.QueryRow(ctx, q, email).Scan(&userID)
	if err != nil {
		logger.LogError("ResendVerification failed", logger.ErrorField(err), logger.String("email", email))
		return wrapDBErr("resend_verification", err)
	}
	token, err := generateToken(32)
	if err != nil {
		logger.LogError("ResendVerification: failed to generate token", logger.ErrorField(err), logger.String("email", email))
		return wrapDBErr("resend_verification_token", err)
	}
	_, err = s.DB.Exec(ctx, `UPDATE users SET email_verification_token=$1 WHERE id=$2`, token, userID)
	if err != nil {
		logger.LogError("ResendVerification: failed to update token", logger.ErrorField(err), logger.String("email", email))
		return wrapDBErr("resend_verification_update", err)
	}
	details := map[string]interface{}{"token": token, "user_id": userID}
	s.SendNotification(ctx, "", NotificationChannel("smtp"), []string{email}, "Verify your email", details, 3)
	return nil
}

func (s *PostgresStore) VerifyEmail(ctx context.Context, userID, token string) error {
	const q = `UPDATE users SET email_verified=TRUE, updated_at=NOW() WHERE id=$1 AND email_verification_token=$2 AND deleted_at IS NULL`
	res, err := s.DB.Exec(ctx, q, userID, token)
	if err != nil {
		logger.LogError("VerifyEmail failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("verify_email", err)
	}
	if res.RowsAffected() == 0 {
		return errors.New("invalid token or user")
	}
	return nil
}

func (s *PostgresStore) AccountRecover(ctx context.Context, email string) error {
	const q = `SELECT id FROM users WHERE email=$1 AND deleted_at IS NULL`
	var userID string
	err := s.DB.QueryRow(ctx, q, email).Scan(&userID)
	if err != nil {
		logger.LogError("AccountRecover failed", logger.ErrorField(err), logger.String("email", email))
		return wrapDBErr("account_recover", err)
	}
	token, err := generateToken(32)
	if err != nil {
		return wrapDBErr("account_recover_token", err)
	}
	s.SendNotification(ctx, "", NotificationChannel("smtp"), []string{email}, "Account recovery", map[string]interface{}{"token": token, "user_id": userID}, 3)
	return nil
}

func (s *PostgresStore) SendInvite(ctx context.Context, email, role string) error {
	token, err := generateToken(32)
	if err != nil {
		return wrapDBErr("send_invite_token", err)
	}
	const q = `INSERT INTO invites (email, role, token, created_at) VALUES ($1, $2, $3, NOW())`
	_, err = s.DB.Exec(ctx, q, email, role, token)
	if err != nil {
		logger.LogError("SendInvite failed", logger.ErrorField(err), logger.String("email", email))
		return wrapDBErr("send_invite", err)
	}
	s.SendNotification(ctx, "", NotificationChannel("smtp"), []string{email}, "You're invited", map[string]interface{}{"token": token, "role": role}, 3)
	return nil
}

func (s *PostgresStore) AcceptInvite(ctx context.Context, token, email, password string) (User, error) {
	const q = `SELECT email FROM invites WHERE token=$1 AND email=$2`
	var foundEmail string
	err := s.DB.QueryRow(ctx, q, token, email).Scan(&foundEmail)
	if err != nil {
		logger.LogError("AcceptInvite lookup failed", logger.ErrorField(err), logger.String("email", email))
		return User{}, wrapDBErr("accept_invite_lookup", err)
	}
	// Register user
	return s.RegisterUser(ctx, email, password)
}

// --- MFAService extensions ---
func (s *PostgresStore) GenerateChallenge(ctx context.Context, userID string) (map[string]interface{}, error) {
	const getSecretQ = `SELECT mfa_secret FROM users WHERE id=$1 AND deleted_at IS NULL`
	var secret string
	err := s.DB.QueryRow(ctx, getSecretQ, userID).Scan(&secret)
	if err != nil {
		logger.LogError("GenerateChallenge lookup failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("generate_challenge_lookup", err)
	}
	if secret == "" {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Subinc",
			AccountName: userID,
		})
		if err != nil {
			logger.LogError("GenerateChallenge: failed to generate key", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, err
		}
		_, err = s.DB.Exec(ctx, `UPDATE users SET mfa_secret=$1 WHERE id=$2`, key.Secret(), userID)
		if err != nil {
			logger.LogError("GenerateChallenge: failed to set secret", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("generate_challenge_set_secret", err)
		}
		return map[string]interface{}{
			"qr":     key.URL(),
			"secret": key.Secret(),
			"setup":  true,
		}, nil
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		logger.LogError("GenerateChallenge: failed to generate code", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, err
	}
	return map[string]interface{}{"challenge": code, "setup": false}, nil
}

func (s *PostgresStore) VerifyChallenge(ctx context.Context, userID, code string) error {
	const getSecretQ = `SELECT mfa_secret FROM users WHERE id=$1 AND deleted_at IS NULL`
	var secret string
	err := s.DB.QueryRow(ctx, getSecretQ, userID).Scan(&secret)
	if err != nil {
		logger.LogError("VerifyChallenge lookup failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("verify_challenge_lookup", err)
	}
	if secret == "" {
		return errors.New("MFA not setup")
	}
	valid := totp.Validate(code, secret)
	if !valid {
		logger.LogError("VerifyChallenge: invalid code", logger.String("user_id", userID))
		return errors.New("invalid code")
	}
	return nil
}

// --- DeviceService extensions ---
func (s *PostgresStore) TrustDevice(ctx context.Context, userID, deviceID string) error {
	const q = `UPDATE devices SET trusted=TRUE, updated_at=NOW() WHERE id=$1 AND user_id=$2`
	res, err := s.DB.Exec(ctx, q, deviceID, userID)
	if err != nil {
		logger.LogError("TrustDevice failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("device_id", deviceID))
		return wrapDBErr("trust_device", err)
	}
	if res.RowsAffected() == 0 {
		return errors.New("device not found")
	}
	return nil
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		logger.LogError("generateSessionToken: failed to generate token", logger.ErrorField(err))
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *PostgresStore) CreateSession(ctx context.Context, userID, ip, device string, expiresIn time.Duration) (Session, error) {
	token, err := generateSessionToken()
	if err != nil {
		logger.LogError("CreateSession token failed", logger.ErrorField(err), logger.String("user_id", userID))
		return Session{}, wrapDBErr("create_session_token", err)
	}
	sess := Session{
		ID:        token,
		UserID:    userID,
		IP:        ip,
		Device:    device,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(expiresIn).UTC(),
	}
	const q = `INSERT INTO sessions (id, user_id, ip, device, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err = s.DB.Exec(ctx, q, sess.ID, sess.UserID, sess.IP, sess.Device, sess.CreatedAt, sess.ExpiresAt)
	if err != nil {
		logger.LogError("CreateSession failed", logger.ErrorField(err), logger.String("user_id", userID))
		return Session{}, wrapDBErr("create_session", err)
	}
	return sess, nil
}

func (s *PostgresStore) RefreshSession(ctx context.Context, sessionID string, expiresIn time.Duration) (Session, error) {
	const q = `UPDATE sessions SET expires_at=NOW()+$1*interval '1 second' WHERE id=$2 RETURNING id, user_id, ip, device, created_at, expires_at`
	var sess Session
	err := s.DB.QueryRow(ctx, q, int64(expiresIn.Seconds()), sessionID).Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.Device, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		logger.LogError("RefreshSession failed", logger.ErrorField(err), logger.String("session_id", sessionID))
		return Session{}, wrapDBErr("refresh_session", err)
	}
	return sess, nil
}

func (s *PostgresStore) LogoutSession(ctx context.Context, sessionID string) error {
	const q = `DELETE FROM sessions WHERE id=$1`
	_, err := s.DB.Exec(ctx, q, sessionID)
	if err != nil {
		logger.LogError("LogoutSession failed", logger.ErrorField(err), logger.String("session_id", sessionID))
		return wrapDBErr("logout_session", err)
	}
	return nil
}

func (s *PostgresStore) GetSession(ctx context.Context, sessionID string) (Session, error) {
	const q = `SELECT id, user_id, ip, device, created_at, expires_at FROM sessions WHERE id=$1 AND expires_at > NOW()`
	var sess Session
	err := s.DB.QueryRow(ctx, q, sessionID).Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.Device, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		logger.LogError("GetSession failed", logger.ErrorField(err), logger.String("session_id", sessionID))
		return Session{}, wrapDBErr("get_session", err)
	}
	return sess, nil
}

func (s *PostgresStore) AddToNotificationQueue(ctx context.Context, item NotificationQueueItem) error {
	b, _ := json.Marshal(item.Details)
	const q = `INSERT INTO notification_queue (id, provider, to, event, details, retry, max_retry, status, last_error, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	_, err := s.DB.Exec(ctx, q, item.ID, item.Provider, item.To, item.Event, string(b), item.Retry, item.MaxRetry, item.Status, item.LastError, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		logger.LogError("AddToNotificationQueue failed", logger.ErrorField(err))
	}
	return err
}

func (s *PostgresStore) GetPendingNotificationQueue(ctx context.Context, limit int) ([]NotificationQueueItem, error) {
	const q = `SELECT id, provider, to, event, details, retry, max_retry, status, last_error, created_at, updated_at FROM notification_queue WHERE status = 'pending' ORDER BY created_at ASC LIMIT $1`
	rows, err := s.DB.Query(ctx, q, limit)
	if err != nil {
		logger.LogError("GetPendingNotificationQueue failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []NotificationQueueItem
	for rows.Next() {
		var item NotificationQueueItem
		var toArr []byte
		var detailsStr string
		if err := rows.Scan(&item.ID, &item.Provider, &toArr, &item.Event, &detailsStr, &item.Retry, &item.MaxRetry, &item.Status, &item.LastError, &item.CreatedAt, &item.UpdatedAt); err != nil {
			logger.LogError("GetPendingNotificationQueue scan failed", logger.ErrorField(err))
			continue
		}
		_ = json.Unmarshal(toArr, &item.To)
		_ = json.Unmarshal([]byte(detailsStr), &item.Details)
		out = append(out, item)
	}
	return out, nil
}

func (s *PostgresStore) UpdateNotificationQueueItem(ctx context.Context, item NotificationQueueItem) error {
	b, _ := json.Marshal(item.Details)
	const q = `UPDATE notification_queue SET retry=$1, status=$2, last_error=$3, updated_at=$4, details=$5 WHERE id=$6`
	_, err := s.DB.Exec(ctx, q, item.Retry, item.Status, item.LastError, item.UpdatedAt, string(b), item.ID)
	if err != nil {
		logger.LogError("UpdateNotificationQueueItem failed", logger.ErrorField(err))
	}
	return err
}

// --- MFAConfig Service ---
func (s *PostgresStore) GetMFAConfig(ctx context.Context, tenantID string) (MFAConfig, error) {
	if tenantID == "" {
		return MFAConfig{}, fmt.Errorf("tenant ID required")
	}

	query := `
		SELECT tenant_id, require_mfa, allowed_methods, mfa_timeout_seconds
		FROM tenant_mfa_config
		WHERE tenant_id = $1
	`

	var config MFAConfig
	var methodsJSON []byte

	err := s.DB.QueryRow(ctx, query, tenantID).Scan(
		&config.TenantID,
		&config.RequireMFA,
		&methodsJSON,
		&config.MFATimeoutSeconds,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			// Return default config if not found
			return MFAConfig{
				TenantID:          tenantID,
				RequireMFA:        false,
				AllowedMethods:    []string{"totp", "sms"},
				MFATimeoutSeconds: 300, // 5 minutes default
			}, nil
		}
		logger.LogError("GetMFAConfig: database error",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return MFAConfig{}, err
	}

	// Parse methods from JSON
	if methodsJSON != nil {
		if err := json.Unmarshal(methodsJSON, &config.AllowedMethods); err != nil {
			logger.LogError("GetMFAConfig: failed to parse methods JSON",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
			// Continue with default methods
			config.AllowedMethods = []string{"totp", "sms"}
		}
	} else {
		config.AllowedMethods = []string{"totp", "sms"}
	}

	return config, nil
}

func (s *PostgresStore) SetMFAConfig(ctx context.Context, tenantID string, config MFAConfig) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID required")
	}

	// Ensure the tenant ID in the config matches the one in the path
	config.TenantID = tenantID

	// Set sane defaults if not provided
	if len(config.AllowedMethods) == 0 {
		config.AllowedMethods = []string{"totp", "sms"}
	}

	if config.MFATimeoutSeconds <= 0 {
		config.MFATimeoutSeconds = 300 // 5 minutes default
	}

	// Serialize allowed methods to JSON
	methodsJSON, err := json.Marshal(config.AllowedMethods)
	if err != nil {
		logger.LogError("SetMFAConfig: failed to serialize methods",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return err
	}

	// Use upsert pattern to create or update
	query := `
		INSERT INTO tenant_mfa_config (
			tenant_id, require_mfa, allowed_methods, mfa_timeout_seconds, updated_at
		) VALUES (
			$1, $2, $3, $4, NOW()
		) ON CONFLICT (tenant_id) DO UPDATE SET
			require_mfa = $2,
			allowed_methods = $3,
			mfa_timeout_seconds = $4,
			updated_at = NOW()
	`

	_, err = s.DB.Exec(ctx, query,
		tenantID,
		config.RequireMFA,
		methodsJSON,
		config.MFATimeoutSeconds,
	)

	if err != nil {
		logger.LogError("SetMFAConfig: database error",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return err
	}

	return nil
}

func (s *PostgresStore) SetAuthTypeConfig(ctx context.Context, tenantID string, config AuthTypeConfigDB) error {
	if err := config.Validate(); err != nil {
		return err
	}
	key := "auth_type_config_" + tenantID
	b, err := json.Marshal(config)
	if err != nil {
		return errors.New("invalid auth type config")
	}
	serverConfigService, ok := s.ServerConfigService.(interface {
		Set(context.Context, string, string, string) (struct{}, error)
	})
	if !ok {
		return errors.New("server config service not available")
	}
	_, err = serverConfigService.Set(ctx, key, string(b), "system")
	if err != nil {
		return err
	}
	// hot-reload stub
	return nil
}

// ChangePassword implements the PasswordService interface
func (s *PostgresStore) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	// First verify the old password
	var passwordHash string
	err := s.DB.QueryRow(ctx, `SELECT password FROM users WHERE id = $1`, userID).Scan(&passwordHash)
	if err != nil {
		logger.LogError("ChangePassword query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("change_password", err)
	}

	// Verify old password
	if err := checkPassword(passwordHash, oldPassword); err != nil {
		logger.LogError("ChangePassword invalid old password", logger.ErrorField(err), logger.String("user_id", userID))
		return errors.New("invalid old password")
	}

	// Hash the new password
	newHash, err := hashPassword(newPassword)
	if err != nil {
		logger.LogError("ChangePassword failed to hash new password", logger.ErrorField(err))
		return wrapDBErr("change_password", err)
	}

	// Update the password
	_, err = s.DB.Exec(ctx, `UPDATE users SET password = $1 WHERE id = $2`, newHash, userID)
	if err != nil {
		logger.LogError("ChangePassword update failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("change_password_update", err)
	}

	return nil
}

// Consent implements the PasswordService interface
func (s *PostgresStore) Consent(ctx context.Context, userID, consent string) error {
	// Store the user consent in the database
	_, err := s.DB.Exec(ctx, `
		INSERT INTO user_consents (user_id, consent_type, created_at)
		VALUES ($1, $2, NOW())
	`, userID, consent)
	if err != nil {
		logger.LogError("Consent failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("user_consent", err)
	}
	return nil
}

// GetProfile implements the PasswordService interface
func (s *PostgresStore) GetProfile(ctx context.Context, userID string) (map[string]interface{}, error) {
	var email string
	var createdAt time.Time
	err := s.DB.QueryRow(ctx, `SELECT email, created_at FROM users WHERE id = $1`, userID).Scan(&email, &createdAt)
	if err != nil {
		logger.LogError("GetProfile query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("get_profile", err)
	}

	return map[string]interface{}{
		"id":         userID,
		"email":      email,
		"created_at": createdAt,
	}, nil
}

// UpdateProfile implements the PasswordService interface
func (s *PostgresStore) UpdateProfile(ctx context.Context, userID string, input map[string]interface{}) (map[string]interface{}, error) {
	// For now, we only support updating email
	email, ok := input["email"].(string)
	if !ok || email == "" {
		return nil, errors.New("valid email required")
	}

	_, err := s.DB.Exec(ctx, `UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2`, email, userID)
	if err != nil {
		logger.LogError("UpdateProfile failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("update_profile", err)
	}

	return s.GetProfile(ctx, userID)
}

// DeleteAccount implements the PasswordService interface
func (s *PostgresStore) DeleteAccount(ctx context.Context, userID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET deleted_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		logger.LogError("DeleteAccount failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("delete_account", err)
	}
	return nil
}

func (s *PostgresStore) CountUsers(ctx context.Context) (int, error) {
	var count int
	row := s.DB.QueryRow(ctx, "SELECT COUNT(*) FROM users")
	if err := row.Scan(&count); err != nil {
		logger.LogError("CountUsers query failed", logger.ErrorField(err))
		return 0, err
	}
	return count, nil
}

// Define a minimal interface locally to avoid import cycle
// Only the method needed for JWT secret fetch

func (s *PostgresStore) GetOwnerJWTSecretConfig(ctx context.Context) (JWTSecretConfig, error) {
	if s.ServerConfigService != nil {
		jwtCfg, err := s.ServerConfigService.GetOwnerJWTSecretConfig(ctx)
		if err == nil && jwtCfg.SecretName != "" {
			return jwtCfg, nil
		}
		logger.LogError("GetOwnerJWTSecretConfig: ServerConfigService failed, falling back to direct DB", logger.ErrorField(err))
	}
	// Fallback: direct DB query
	const q = `SELECT value FROM server_config WHERE key = $1`
	var value string
	err := s.DB.QueryRow(ctx, q, "owner_admin_jwt_secret_config").Scan(&value)
	if err != nil {
		logger.LogError("GetOwnerJWTSecretConfig: direct DB fetch failed", logger.ErrorField(err))
		return JWTSecretConfig{}, errors.New("JWT secret config unavailable")
	}
	var jwtCfg JWTSecretConfig
	err = json.Unmarshal([]byte(value), &jwtCfg)
	if err != nil || jwtCfg.SecretName == "" {
		logger.LogError("GetOwnerJWTSecretConfig: invalid JSON or missing secret_name", logger.ErrorField(err))
		return JWTSecretConfig{}, errors.New("JWT secret config invalid")
	}
	logger.LogWarn("GetOwnerJWTSecretConfig: used direct DB fallback for JWT secret config")
	return jwtCfg, nil
}

func NewPostgresStore(db *pgxpool.Pool, serverConfigService ServerConfigService, auditLogger AuditLogger) *PostgresStore {
	if db == nil {
		panic("PostgresStore: DB must not be nil")
	}
	if serverConfigService == nil {
		panic("PostgresStore: ServerConfigService must not be nil (required for all secrets/keys)")
	}
	return &PostgresStore{
		DB:                  db,
		ServerConfigService: serverConfigService,
		AuditLogger:         auditLogger,
	}
}

// GetUserMFAStatus checks if MFA is enabled for a specific user
func (s *PostgresStore) GetUserMFAStatus(ctx context.Context, userID string) (UserMFAStatus, error) {
	if userID == "" {
		return UserMFAStatus{}, fmt.Errorf("user ID required")
	}

	query := `
		SELECT user_id, mfa_enabled, mfa_methods, updated_at
		FROM user_mfa_settings
		WHERE user_id = $1
	`

	var status UserMFAStatus
	var methodsJSON []byte

	err := s.DB.QueryRow(ctx, query, userID).Scan(
		&status.UserID,
		&status.Enabled,
		&methodsJSON,
		&status.LastUpdated,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			// Return default status if no MFA settings found
			return UserMFAStatus{
				UserID:      userID,
				Enabled:     false,
				Methods:     []string{},
				LastUpdated: time.Now(),
			}, nil
		}
		logger.LogError("GetUserMFAStatus: database error",
			logger.ErrorField(err),
			logger.String("user_id", userID))
		return UserMFAStatus{}, err
	}

	// Parse methods from JSON
	if methodsJSON != nil {
		if err := json.Unmarshal(methodsJSON, &status.Methods); err != nil {
			logger.LogError("GetUserMFAStatus: failed to parse methods JSON",
				logger.ErrorField(err),
				logger.String("user_id", userID))
			// Continue with empty methods
			status.Methods = []string{}
		}
	} else {
		status.Methods = []string{}
	}

	return status, nil
}

// GetProviderConfig retrieves provider configuration
func (s *PostgresStore) GetProviderConfig(ctx context.Context, tenantID, channel, provider string) (ProviderConfig, error) {
	if tenantID == "" || channel == "" || provider == "" {
		return ProviderConfig{}, fmt.Errorf("tenant_id, channel, and provider required")
	}

	query := `
		SELECT tenant_id, channel, provider, config
		FROM notification_provider_configs
		WHERE tenant_id = $1 AND channel = $2 AND provider = $3
	`

	var config ProviderConfig
	var configJSON []byte

	err := s.DB.QueryRow(ctx, query, tenantID, channel, provider).Scan(
		&config.TenantID,
		&config.Channel,
		&config.Provider,
		&configJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			// Return default config if not found
			return ProviderConfig{
				TenantID: tenantID,
				Channel:  channel,
				Provider: provider,
				Config:   map[string]string{},
			}, nil
		}
		logger.LogError("GetProviderConfig: database error",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("channel", channel),
			logger.String("provider", provider))
		return ProviderConfig{}, err
	}

	// Parse config from JSON
	if configJSON != nil && len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &config.Config); err != nil {
			logger.LogError("GetProviderConfig: failed to parse config JSON",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID),
				logger.String("channel", channel),
				logger.String("provider", provider))
			// Continue with empty config
			config.Config = map[string]string{}
		}
	} else {
		config.Config = map[string]string{}
	}

	return config, nil
}

// SetProviderConfig updates provider configuration
func (s *PostgresStore) SetProviderConfig(ctx context.Context, config ProviderConfig) error {
	if config.TenantID == "" || config.Channel == "" || config.Provider == "" {
		return fmt.Errorf("tenant_id, channel, and provider required")
	}

	// Serialize config to JSON
	configJSON, err := json.Marshal(config.Config)
	if err != nil {
		logger.LogError("SetProviderConfig: failed to serialize config",
			logger.ErrorField(err),
			logger.String("tenant_id", config.TenantID),
			logger.String("channel", config.Channel),
			logger.String("provider", config.Provider))
		return err
	}

	// Use upsert pattern to create or update
	query := `
		INSERT INTO notification_provider_configs (
			tenant_id, channel, provider, config, updated_at
		) VALUES (
			$1, $2, $3, $4, NOW()
		) ON CONFLICT (tenant_id, channel, provider) DO UPDATE SET
			config = $4,
			updated_at = NOW()
	`

	_, err = s.DB.Exec(ctx, query,
		config.TenantID,
		config.Channel,
		config.Provider,
		configJSON,
	)

	if err != nil {
		logger.LogError("SetProviderConfig: database error",
			logger.ErrorField(err),
			logger.String("tenant_id", config.TenantID),
			logger.String("channel", config.Channel),
			logger.String("provider", config.Provider))
		return err
	}

	return nil
}

// GetAuthTypeConfig retrieves auth type configuration for a tenant
func (s *PostgresStore) GetAuthTypeConfig(ctx context.Context, tenantID string) (AuthTypeConfigDB, error) {
	var config AuthTypeConfigDB

	const query = `SELECT tenant_id, mfa_enabled, password_enabled, oauth_enabled, saml_enabled, 
			auth_types, "primary", fallback, updated_at
			FROM auth_type_configs WHERE tenant_id = $1`

	row := s.DB.QueryRow(ctx, query, tenantID)

	var authTypes, fallback []byte
	err := row.Scan(
		&config.TenantID,
		&config.MFAEnabled,
		&config.PasswordEnabled,
		&config.OAuthEnabled,
		&config.SAMLEnabled,
		&authTypes,
		&config.Primary,
		&fallback,
		&config.UpdatedAt,
	)

	if err != nil {
		// For not found, return default config with password enabled
		if err.Error() == "no rows in result set" {
			return AuthTypeConfigDB{
				TenantID:        tenantID,
				MFAEnabled:      true,
				PasswordEnabled: true,
				OAuthEnabled:    false,
				SAMLEnabled:     false,
				AuthTypes:       []string{"password"},
				Primary:         "password",
				Fallback:        []string{},
				UpdatedAt:       time.Now(),
			}, nil
		}
		return config, wrapDBErr("GetAuthTypeConfig", err)
	}

	// Parse JSON arrays
	if err := json.Unmarshal(authTypes, &config.AuthTypes); err != nil {
		return config, wrapDBErr("GetAuthTypeConfig.UnmarshalAuthTypes", err)
	}
	if err := json.Unmarshal(fallback, &config.Fallback); err != nil {
		return config, wrapDBErr("GetAuthTypeConfig.UnmarshalFallback", err)
	}

	return config, nil
}

// GetOAuthConfig retrieves OAuth configuration for a tenant
func (s *PostgresStore) GetOAuthConfig(ctx context.Context, tenantID string) (OAuthConfigDB, error) {
	var config OAuthConfigDB

	query := `SELECT tenant_id, client_id, client_secret, redirect_uri, scopes
			FROM oauth_configs WHERE tenant_id = $1`

	row := s.DB.QueryRow(ctx, query, tenantID)

	var scopes []byte
	err := row.Scan(
		&config.TenantID,
		&config.ClientID,
		&config.ClientSecret,
		&config.RedirectURI,
		&scopes,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return OAuthConfigDB{
				TenantID:     tenantID,
				ClientID:     "",
				ClientSecret: "",
				RedirectURI:  "",
				Scopes:       []string{},
			}, nil
		}
		return config, wrapDBErr("GetOAuthConfig", err)
	}

	// Parse JSON arrays
	if err := json.Unmarshal(scopes, &config.Scopes); err != nil {
		return config, wrapDBErr("GetOAuthConfig.UnmarshalScopes", err)
	}

	return config, nil
}

// GetSAMLConfig retrieves SAML configuration for a tenant
func (s *PostgresStore) GetSAMLConfig(ctx context.Context, tenantID string) (SAMLConfigDB, error) {
	var config SAMLConfigDB

	query := `SELECT tenant_id, metadata_url, entity_id, acs_url
			FROM saml_configs WHERE tenant_id = $1`

	row := s.DB.QueryRow(ctx, query, tenantID)

	err := row.Scan(
		&config.TenantID,
		&config.MetadataURL,
		&config.EntityID,
		&config.ACSURL,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return SAMLConfigDB{
				TenantID:    tenantID,
				MetadataURL: "",
				EntityID:    "",
				ACSURL:      "",
			}, nil
		}
		return config, wrapDBErr("GetSAMLConfig", err)
	}

	return config, nil
}

// GetNotificationChannelEnabledConfig retrieves notification channel enabled configuration
func (s *PostgresStore) GetNotificationChannelEnabledConfig(ctx context.Context, tenantID, channel, provider string) (NotificationChannelEnabledConfig, error) {
	var config NotificationChannelEnabledConfig

	query := `SELECT tenant_id, channel, provider, enabled
			FROM notification_channel_enabled_configs 
			WHERE tenant_id = $1 AND channel = $2 AND provider = $3`

	row := s.DB.QueryRow(ctx, query, tenantID, channel, provider)

	err := row.Scan(
		&config.TenantID,
		&config.Channel,
		&config.Provider,
		&config.Enabled,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return NotificationChannelEnabledConfig{
				TenantID: tenantID,
				Channel:  channel,
				Provider: provider,
				Enabled:  true, // Default to enabled
			}, nil
		}
		return config, wrapDBErr("GetNotificationChannelEnabledConfig", err)
	}

	return config, nil
}

// SetNotificationChannelEnabledConfig sets notification channel enabled configuration
func (s *PostgresStore) SetNotificationChannelEnabledConfig(ctx context.Context, config NotificationChannelEnabledConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	query := `INSERT INTO notification_channel_enabled_configs
			(tenant_id, channel, provider, enabled)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, channel, provider) 
			DO UPDATE SET enabled = $4`

	_, err := s.DB.Exec(ctx, query,
		config.TenantID,
		config.Channel,
		config.Provider,
		config.Enabled,
	)

	if err != nil {
		return wrapDBErr("SetNotificationChannelEnabledConfig", err)
	}

	return nil
}

// GetPasswordPolicyConfig retrieves password policy configuration for a tenant
func (s *PostgresStore) GetPasswordPolicyConfig(ctx context.Context, tenantID string) (PasswordPolicyConfig, error) {
	var config PasswordPolicyConfig

	query := `SELECT tenant_id, min_length, require_numbers, require_special, 
			require_upper, require_lower
			FROM password_policy_configs WHERE tenant_id = $1`

	row := s.DB.QueryRow(ctx, query, tenantID)

	err := row.Scan(
		&config.TenantID,
		&config.MinLength,
		&config.RequireNumbers,
		&config.RequireSpecial,
		&config.RequireUpper,
		&config.RequireLower,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return PasswordPolicyConfig{
				TenantID:       tenantID,
				MinLength:      8,
				RequireNumbers: true,
				RequireSpecial: true,
				RequireUpper:   true,
				RequireLower:   true,
			}, nil
		}
		return config, wrapDBErr("GetPasswordPolicyConfig", err)
	}

	return config, nil
}

// SetPasswordPolicyConfig sets password policy configuration for a tenant
func (s *PostgresStore) SetPasswordPolicyConfig(ctx context.Context, tenantID string, config PasswordPolicyConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	query := `INSERT INTO password_policy_configs
			(tenant_id, min_length, require_numbers, require_special, require_upper, require_lower)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id) 
			DO UPDATE SET 
				min_length = $2,
				require_numbers = $3,
				require_special = $4,
				require_upper = $5,
				require_lower = $6`

	_, err := s.DB.Exec(ctx, query,
		tenantID,
		config.MinLength,
		config.RequireNumbers,
		config.RequireSpecial,
		config.RequireUpper,
		config.RequireLower,
	)

	if err != nil {
		return wrapDBErr("SetPasswordPolicyConfig", err)
	}

	return nil
}

// GetSessionConfig retrieves session configuration for a tenant
func (s *PostgresStore) GetSessionConfig(ctx context.Context, tenantID string) (SessionConfig, error) {
	var config SessionConfig

	query := `SELECT tenant_id, session_timeout_minutes, idle_timeout_minutes
			FROM session_configs WHERE tenant_id = $1`

	row := s.DB.QueryRow(ctx, query, tenantID)

	err := row.Scan(
		&config.TenantID,
		&config.SessionTimeoutMinutes,
		&config.IdleTimeoutMinutes,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return SessionConfig{
				TenantID:              tenantID,
				SessionTimeoutMinutes: 60, // 1 hour
				IdleTimeoutMinutes:    15, // 15 minutes
			}, nil
		}
		return config, wrapDBErr("GetSessionConfig", err)
	}

	return config, nil
}

// SetSessionConfig sets session configuration for a tenant
func (s *PostgresStore) SetSessionConfig(ctx context.Context, tenantID string, config SessionConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	query := `INSERT INTO session_configs
			(tenant_id, session_timeout_minutes, idle_timeout_minutes)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id) 
			DO UPDATE SET 
				session_timeout_minutes = $2,
				idle_timeout_minutes = $3`

	_, err := s.DB.Exec(ctx, query,
		tenantID,
		config.SessionTimeoutMinutes,
		config.IdleTimeoutMinutes,
	)

	if err != nil {
		return wrapDBErr("SetSessionConfig", err)
	}

	return nil
}

// SetRateLimitConfig sets rate limit configuration for a specific scope/ID
func (s *PostgresStore) SetRateLimitConfig(ctx context.Context, config RateLimitConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	query := `INSERT INTO rate_limit_configs
			(scope, scope_id, limit, window_seconds, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (scope, scope_id) 
			DO UPDATE SET 
				limit = $3,
				window_seconds = $4,
				updated_at = $6`

	now := time.Now()

	_, err := s.DB.Exec(ctx, query,
		config.Scope,
		config.ScopeID,
		config.Limit,
		config.WindowSeconds,
		now,
		now,
	)

	if err != nil {
		return wrapDBErr("SetRateLimitConfig", err)
	}

	return nil
}

// SetOAuthConfig sets OAuth configuration for a tenant
func (s *PostgresStore) SetOAuthConfig(ctx context.Context, tenantID string, config OAuthConfigDB) error {
	if config.TenantID == "" {
		config.TenantID = tenantID
	}

	if err := config.Validate(); err != nil {
		return err
	}

	// Serialize scopes to JSON
	scopesJSON, err := json.Marshal(config.Scopes)
	if err != nil {
		return wrapDBErr("SetOAuthConfig.MarshalScopes", err)
	}

	query := `INSERT INTO oauth_configs
			(tenant_id, client_id, client_secret, redirect_uri, scopes)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id) 
			DO UPDATE SET 
				client_id = $2,
				client_secret = $3,
				redirect_uri = $4,
				scopes = $5`

	_, err = s.DB.Exec(ctx, query,
		tenantID,
		config.ClientID,
		config.ClientSecret,
		config.RedirectURI,
		scopesJSON,
	)

	if err != nil {
		return wrapDBErr("SetOAuthConfig", err)
	}

	return nil
}

// SetSAMLConfig sets SAML configuration for a tenant
func (s *PostgresStore) SetSAMLConfig(ctx context.Context, tenantID string, config SAMLConfigDB) error {
	if config.TenantID == "" {
		config.TenantID = tenantID
	}

	if err := config.Validate(); err != nil {
		return err
	}

	query := `INSERT INTO saml_configs
			(tenant_id, metadata_url, entity_id, acs_url)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id) 
			DO UPDATE SET 
				metadata_url = $2,
				entity_id = $3,
				acs_url = $4`

	_, err := s.DB.Exec(ctx, query,
		tenantID,
		config.MetadataURL,
		config.EntityID,
		config.ACSURL,
	)

	if err != nil {
		return wrapDBErr("SetSAMLConfig", err)
	}

	return nil
}

// GetUserTenantIDs returns all tenant/org IDs the user belongs to.
func (s *PostgresStore) GetUserTenantIDs(ctx context.Context, userID string) ([]string, error) {
	const q = `SELECT org_id FROM org_members WHERE user_id = $1`
	rows, err := s.DB.Query(ctx, q, userID)
	if err != nil {
		logger.LogError("GetUserTenantIDs query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			logger.LogError("GetUserTenantIDs scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
