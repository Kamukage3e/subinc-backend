package security_management

import (
	"bytes"
	"context"
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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

var (
	ErrMissingID       = errors.New("missing id for audit log")
	ErrInvalidAuditLog = errors.New("invalid audit log: missing required fields")
)

func NewPostgresSecurityEventStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListUserSecurityEvents(ctx context.Context, userID string) ([]SecurityEvent, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, event_type, details, created_at FROM security_events WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		s.logger.Error("ListUserSecurityEvents query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_security_events", err)
	}
	defer rows.Close()
	var events []SecurityEvent
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.EventType, &e.Details, &e.CreatedAt); err != nil {
			s.logger.Error("ListUserSecurityEvents scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_security_events_scan", err)
		}
		events = append(events, e)
	}
	return events, nil
}

func NewPostgresLoginHistoryStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListUserLoginHistory(ctx context.Context, userID string) ([]LoginHistory, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, ip, device, location, success, created_at FROM login_history WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		s.logger.Error("ListUserLoginHistory query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_login_history", err)
	}
	defer rows.Close()
	var history []LoginHistory
	for rows.Next() {
		var h LoginHistory
		if err := rows.Scan(&h.ID, &h.UserID, &h.IP, &h.Device, &h.Location, &h.Success, &h.CreatedAt); err != nil {
			s.logger.Error("ListUserLoginHistory scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_login_history_scan", err)
		}
		history = append(history, h)
	}
	return history, nil
}

func NewPostgresMFAStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) EnableMFA(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET mfa_enabled=TRUE WHERE id=$1`, userID)
	if err != nil {
		s.logger.Error("EnableMFA failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("enable_mfa", err)
	}
	return nil
}

func (s *PostgresStore) DisableMFA(ctx context.Context, userID string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET mfa_enabled=FALSE WHERE id=$1`, userID)
	if err != nil {
		s.logger.Error("DisableMFA failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("disable_mfa", err)
	}
	return nil
}

func NewPostgresPasswordStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ResetUserPassword(ctx context.Context, userID, newPassword string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, newPassword, userID)
	if err != nil {
		s.logger.Error("ResetUserPassword failed", logger.ErrorField(err), logger.String("user_id", userID))
		return wrapDBErr("reset_user_password", err)
	}
	return nil
}

func NewPostgresSessionStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, ip, device, created_at, expires_at FROM sessions WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		s.logger.Error("ListUserSessions query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_sessions", err)
	}
	defer rows.Close()
	var sessions []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.IP, &sess.Device, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			s.logger.Error("ListUserSessions scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_sessions_scan", err)
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

func (s *PostgresStore) RevokeUserSession(ctx context.Context, userID, sessionID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE id=$1 AND user_id=$2`, sessionID, userID)
	if err != nil {
		s.logger.Error("RevokeUserSession failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("session_id", sessionID))
		return wrapDBErr("revoke_user_session", err)
	}
	return nil
}

func NewPostgresSecurityAuditLogStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListSecurityAuditLogs(ctx context.Context, page, pageSize int) ([]SecurityAuditLog, error) {
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, `SELECT id, actor_id, action, target_id, details, created_at FROM security_audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		s.logger.Error("ListSecurityAuditLogs query failed", logger.ErrorField(err))
		return nil, wrapDBErr("list_security_audit_logs", err)
	}
	defer rows.Close()
	var logs []SecurityAuditLog
	for rows.Next() {
		var l SecurityAuditLog
		if err := rows.Scan(&l.ID, &l.ActorID, &l.Action, &l.TargetID, &l.Details, &l.CreatedAt); err != nil {
			s.logger.Error("ListSecurityAuditLogs scan failed", logger.ErrorField(err))
			return nil, wrapDBErr("list_security_audit_logs_scan", err)
		}
		logs = append(logs, l)
	}
	return logs, nil
}

func (s *PostgresStore) CreateSecurityAuditLog(ctx context.Context, log SecurityAuditLog) (SecurityAuditLog, error) {
	if log.ID == "" {
		return SecurityAuditLog{}, wrapDBErr("create_security_audit_log", ErrMissingID)
	}
	if log.ActorID == "" || log.Action == "" || log.TargetID == "" {
		return SecurityAuditLog{}, wrapDBErr("create_security_audit_log", ErrInvalidAuditLog)
	}
	const q = `INSERT INTO security_audit_logs (id, actor_id, action, target_id, details, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, actor_id, action, target_id, details, created_at`
	row := s.db.QueryRow(ctx, q, log.ID, log.ActorID, log.Action, log.TargetID, log.Details, log.CreatedAt)
	var out SecurityAuditLog
	if err := row.Scan(&out.ID, &out.ActorID, &out.Action, &out.TargetID, &out.Details, &out.CreatedAt); err != nil {
		s.logger.Error("CreateSecurityAuditLog failed", logger.ErrorField(err), logger.Any("log", log))
		return SecurityAuditLog{}, wrapDBErr("create_security_audit_log", err)
	}
	return out, nil
}

// --- API Key Store ---

func NewPostgresAPIKeyStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListUserAPIKeys(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, name, key, created_at, revoked_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		s.logger.Error("ListUserAPIKeys query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_api_keys", err)
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Key, &k.CreatedAt, &k.RevokedAt); err != nil {
			s.logger.Error("ListUserAPIKeys scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_api_keys_scan", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *PostgresStore) CreateUserAPIKey(ctx context.Context, userID, name string) (APIKey, error) {
	var key APIKey
	q := `INSERT INTO api_keys (user_id, name, key, created_at) VALUES ($1, $2, gen_random_uuid(), NOW()) RETURNING id, user_id, name, key, created_at, revoked_at`
	err := s.db.QueryRow(ctx, q, userID, name).Scan(&key.ID, &key.UserID, &key.Name, &key.Key, &key.CreatedAt, &key.RevokedAt)
	if err != nil {
		s.logger.Error("CreateUserAPIKey failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("name", name))
		return APIKey{}, wrapDBErr("create_user_api_key", err)
	}
	// Audit log for API key creation
	// s.log.Audit("api_key_created", map[string]interface{}{"user_id": userID, "key_id": key.ID})
	return key, nil
}

func (s *PostgresStore) RevokeUserAPIKey(ctx context.Context, userID, keyID string) error {
	_, err := s.db.Exec(ctx, `UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND user_id=$2`, keyID, userID)
	if err != nil {
		s.logger.Error("RevokeUserAPIKey failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("key_id", keyID))
		return wrapDBErr("revoke_user_api_key", err)
	}
	// Audit log for API key revocation
	// s.log.Audit("api_key_revoked", map[string]interface{}{"user_id": userID, "key_id": keyID})
	return nil
}

// --- Device Store ---

func NewPostgresDeviceStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListUserDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, type, name, ip, created_at, revoked_at FROM devices WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		s.logger.Error("ListUserDevices query failed", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, wrapDBErr("list_user_devices", err)
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Type, &d.Name, &d.IP, &d.CreatedAt, &d.RevokedAt); err != nil {
			s.logger.Error("ListUserDevices scan failed", logger.ErrorField(err), logger.String("user_id", userID))
			return nil, wrapDBErr("list_user_devices_scan", err)
		}
		devices = append(devices, d)
	}
	return devices, nil
}

func (s *PostgresStore) RevokeUserDevice(ctx context.Context, userID, deviceID string) error {
	_, err := s.db.Exec(ctx, `UPDATE devices SET revoked_at=NOW() WHERE id=$1 AND user_id=$2`, deviceID, userID)
	if err != nil {
		s.logger.Error("RevokeUserDevice failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("device_id", deviceID))
		return wrapDBErr("revoke_user_device", err)
	}
	// Audit log for device revocation
	// s.log.Audit("device_revoked", map[string]interface{}{"user_id": userID, "device_id": deviceID})
	return nil
}

// --- Breach Store ---

func NewPostgresBreachStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListBreaches(ctx context.Context, page, pageSize int) ([]Breach, error) {
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, `SELECT id, type, details, detected_at FROM breaches ORDER BY detected_at DESC LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		s.logger.Error("ListBreaches query failed", logger.ErrorField(err))
		return nil, wrapDBErr("list_breaches", err)
	}
	defer rows.Close()
	var breaches []Breach
	for rows.Next() {
		var b Breach
		if err := rows.Scan(&b.ID, &b.Type, &b.Details, &b.DetectedAt); err != nil {
			s.logger.Error("ListBreaches scan failed", logger.ErrorField(err))
			return nil, wrapDBErr("list_breaches_scan", err)
		}
		breaches = append(breaches, b)
	}
	return breaches, nil
}

// --- Security Policy Store ---

func NewPostgresSecurityPolicyStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

func (s *PostgresStore) ListSecurityPolicies(ctx context.Context) ([]SecurityPolicy, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, rules, created_at, updated_at FROM security_policies ORDER BY created_at DESC`)
	if err != nil {
		s.logger.Error("ListSecurityPolicies query failed", logger.ErrorField(err))
		return nil, wrapDBErr("list_security_policies", err)
	}
	defer rows.Close()
	var policies []SecurityPolicy
	for rows.Next() {
		var p SecurityPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Rules, &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("ListSecurityPolicies scan failed", logger.ErrorField(err))
			return nil, wrapDBErr("list_security_policies_scan", err)
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *PostgresStore) CreateSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error) {
	q := `INSERT INTO security_policies (name, rules, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) RETURNING id, name, rules, created_at, updated_at`
	var out SecurityPolicy
	err := s.db.QueryRow(ctx, q, policy.Name, policy.Rules).Scan(&out.ID, &out.Name, &out.Rules, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		s.logger.Error("CreateSecurityPolicy failed", logger.ErrorField(err), logger.String("name", policy.Name))
		return SecurityPolicy{}, wrapDBErr("create_security_policy", err)
	}
	// Audit log for policy creation
	// s.log.Audit("security_policy_created", map[string]interface{}{"policy_id": out.ID})
	return out, nil
}

func (s *PostgresStore) UpdateSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error) {
	q := `UPDATE security_policies SET name=$1, rules=$2, updated_at=NOW() WHERE id=$3 RETURNING id, name, rules, created_at, updated_at`
	var out SecurityPolicy
	err := s.db.QueryRow(ctx, q, policy.Name, policy.Rules, policy.ID).Scan(&out.ID, &out.Name, &out.Rules, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		s.logger.Error("UpdateSecurityPolicy failed", logger.ErrorField(err), logger.String("id", policy.ID))
		return SecurityPolicy{}, wrapDBErr("update_security_policy", err)
	}
	// Audit log for policy update
	// s.log.Audit("security_policy_updated", map[string]interface{}{"policy_id": out.ID})
	return out, nil
}

func (s *PostgresStore) DeleteSecurityPolicy(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM security_policies WHERE id=$1`, id)
	if err != nil {
		s.logger.Error("DeleteSecurityPolicy failed", logger.ErrorField(err), logger.String("id", id))
		return wrapDBErr("delete_security_policy", err)
	}
	// Audit log for policy deletion
	// s.log.Audit("security_policy_deleted", map[string]interface{}{"policy_id": id})
	return nil
}

// --- Error wrapping helper ---
func wrapDBErr(op string, err error) error {
	return &DBError{Op: op, Err: err}
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
		s.logger.Error("GetSecurityAnalytics: ListBreaches failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityAnalytics{}, &DBError{Op: "GetSecurityAnalytics.ListBreaches", Err: err}
	}
	if len(breaches) > 0 {
		risk += float64(len(breaches)) * 10
	}
	var mfaCount int
	row := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id=$1 AND mfa_enabled=TRUE`, tenantID)
	if err := row.Scan(&mfaCount); err != nil {
		s.logger.Error("GetSecurityAnalytics: mfa_count failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityAnalytics{}, &DBError{Op: "GetSecurityAnalytics.mfa_count", Err: err}
	}
	if mfaCount > 0 {
		risk -= 10
	}
	anomalies, err := s.ListAnomalies(ctx, tenantID, 1, 10)
	if err != nil && anomalies == nil {
		s.logger.Error("GetSecurityAnalytics: ListAnomalies failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityAnalytics{}, &DBError{Op: "GetSecurityAnalytics.ListAnomalies", Err: err}
	}
	if len(anomalies) > 0 {
		risk += float64(len(anomalies)) * 5
	}
	row = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM login_history WHERE tenant_id=$1 AND success=FALSE AND created_at > NOW() - INTERVAL '30 days'`, tenantID)
	var failedLogins int
	if err := row.Scan(&failedLogins); err != nil {
		s.logger.Error("GetSecurityAnalytics: failed_logins failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
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
	const q = `SELECT id, type, details, detected_at FROM anomalies WHERE tenant_id = $1 ORDER BY detected_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, q, tenantID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListAnomalies query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, &DBError{Op: "ListAnomalies.query", Err: err}
	}
	defer rows.Close()
	var out []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.Type, &a.Details, &a.DetectedAt); err != nil {
			s.logger.Error("ListAnomalies scan failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
			return nil, &DBError{Op: "ListAnomalies.scan", Err: err}
		}
		out = append(out, a)
	}
	return out, nil
}

// --- Real Anomaly Detection Logic ---

func (s *PostgresStore) DetectAnomalies(ctx context.Context, tenantID string) ([]Anomaly, error) {
	var anomalies []Anomaly
	// 1. Suspicious logins: same user, different geo/IP within 1h
	const suspiciousLoginQ = `SELECT user_id, ip, location, created_at FROM login_history WHERE tenant_id=$1 AND success=TRUE ORDER BY user_id, created_at DESC LIMIT 1000`
	rows, err := s.db.Query(ctx, suspiciousLoginQ, tenantID)
	if err != nil {
		s.logger.Error("DetectAnomalies: suspiciousLoginQ failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	defer rows.Close()
	userLast := make(map[string]struct {
		IP      string
		Loc     string
		Created time.Time
	})
	for rows.Next() {
		var userID, ip, loc string
		var created time.Time
		if err := rows.Scan(&userID, &ip, &loc, &created); err != nil {
			s.logger.Error("DetectAnomalies: scan failed", logger.ErrorField(err))
			continue
		}
		if last, ok := userLast[userID]; ok {
			if last.IP != ip || last.Loc != loc {
				if created.Sub(last.Created) < time.Hour {
					anomalies = append(anomalies, Anomaly{
						ID:         uuidString(),
						Type:       "suspicious_login",
						Details:    "Multiple locations/IPs in 1h for user " + userID,
						DetectedAt: created,
					})
				}
			}
		}
		userLast[userID] = struct {
			IP      string
			Loc     string
			Created time.Time
		}{ip, loc, created}
	}
	// 2. Device changes: new device for user in last 24h
	const deviceQ = `SELECT user_id, type, name, created_at FROM devices WHERE tenant_id=$1 AND created_at > NOW() - INTERVAL '1 day'`
	rows, err = s.db.Query(ctx, deviceQ, tenantID)
	if err == nil {
		for rows.Next() {
			var userID, typ, name string
			var created time.Time
			if err := rows.Scan(&userID, &typ, &name, &created); err == nil {
				anomalies = append(anomalies, Anomaly{
					ID:         uuidString(),
					Type:       "new_device",
					Details:    "New device: " + typ + " " + name + " for user " + userID,
					DetectedAt: created,
				})
			}
		}
	}
	// 3. Brute-force: >5 failed logins for user in 10min
	const bruteQ = `SELECT user_id, COUNT(*) FROM login_history WHERE tenant_id=$1 AND success=FALSE AND created_at > NOW() - INTERVAL '10 minutes' GROUP BY user_id HAVING COUNT(*) > 5`
	rows, err = s.db.Query(ctx, bruteQ, tenantID)
	if err == nil {
		for rows.Next() {
			var userID string
			var count int
			if err := rows.Scan(&userID, &count); err == nil {
				anomalies = append(anomalies, Anomaly{
					ID:         uuidString(),
					Type:       "brute_force",
					Details:    "Brute-force: " + userID + " failed logins: " + itoa(count),
					DetectedAt: time.Now().UTC(),
				})
			}
		}
	}
	// 4. Breach correlation: user in breach and active session
	const breachQ = `SELECT b.details, s.user_id, s.id FROM breaches b JOIN sessions s ON b.details LIKE '%' || s.user_id || '%' WHERE s.tenant_id=$1 AND s.expires_at > NOW()`
	rows, err = s.db.Query(ctx, breachQ, tenantID)
	if err == nil {
		for rows.Next() {
			var breachDetails, userID, sessionID string
			if err := rows.Scan(&breachDetails, &userID, &sessionID); err == nil {
				anomalies = append(anomalies, Anomaly{
					ID:         uuidString(),
					Type:       "breach_active_session",
					Details:    "User " + userID + " in breach and has active session " + sessionID,
					DetectedAt: time.Now().UTC(),
				})
			}
		}
	}
	return anomalies, nil
}

func uuidString() string {
	return time.Now().UTC().Format("20060102150405") + "-" + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}

// --- NotificationService ---

func (s *PostgresStore) GetNotificationConfig(ctx context.Context, tenantID string) (NotificationConfig, error) {
	const q = `SELECT channels, recipients, events, enabled FROM notification_configs WHERE tenant_id = $1`
	row := s.db.QueryRow(ctx, q, tenantID)
	var cfg NotificationConfig
	var channels, events []string
	if err := row.Scan(&channels, &cfg.Recipients, &events, &cfg.Enabled); err != nil {
		s.logger.Error("GetNotificationConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return NotificationConfig{}, err
	}
	cfg.TenantID = tenantID
	for _, ch := range channels {
		cfg.Channels = append(cfg.Channels, NotificationChannel(ch))
	}
	cfg.Events = events
	return cfg, nil
}

func (s *PostgresStore) UpdateNotificationConfig(ctx context.Context, cfg NotificationConfig) error {
	const q = `INSERT INTO notification_configs (tenant_id, channels, recipients, events, enabled) VALUES ($1, $2, $3, $4, $5)
	ON CONFLICT (tenant_id) DO UPDATE SET channels = $2, recipients = $3, events = $4, enabled = $5`
	channels := make([]string, len(cfg.Channels))
	for i, ch := range cfg.Channels {
		channels[i] = string(ch)
	}
	_, err := s.db.Exec(ctx, q, cfg.TenantID, channels, cfg.Recipients, cfg.Events, cfg.Enabled)
	if err != nil {
		s.logger.Error("UpdateNotificationConfig failed", logger.ErrorField(err), logger.String("tenant_id", cfg.TenantID))
		return err
	}
	return nil
}

func (s *PostgresStore) SendNotification(ctx context.Context, tenantID string, event string, details map[string]interface{}) error {
	cfg, err := s.GetNotificationConfig(ctx, tenantID)
	if err != nil {
		s.logger.Error("SendNotification: config fetch failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return &DBError{Op: "SendNotification.config", Err: err}
	}
	if !cfg.Enabled {
		s.logger.Info("SendNotification: notifications disabled", logger.String("tenant_id", tenantID))
		return nil
	}
	for _, ch := range cfg.Channels {
		switch ch {
		case NotificationEmail:
			err := sendEmailProvider("smtp", cfg.Recipients, event, details)
			if err != nil {
				s.logger.Error("SendNotification: email failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
				return &DBError{Op: "SendNotification.email", Err: err}
			}
		case NotificationSMS:
			err := sendSMSProvider("twilio", cfg.Recipients, event, details)
			if err != nil {
				s.logger.Error("SendNotification: sms failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
				return &DBError{Op: "SendNotification.sms", Err: err}
			}
		case NotificationSlack:
			err := sendChatProvider("slack", cfg.Recipients, event, details)
			if err != nil {
				s.logger.Error("SendNotification: slack failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
				return &DBError{Op: "SendNotification.slack", Err: err}
			}
		}
	}
	return nil
}

func sendEmailProvider(provider string, recipients []string, event string, details map[string]interface{}) error {
	enabled, ok := emailEnabled[provider]
	if !ok || !enabled {
		return nil
	}
	cfg := emailConfig[provider]
	host := cfg["host"]
	port := cfg["port"]
	user := cfg["user"]
	pass := cfg["pass"]
	from := cfg["from"]
	if host == "" || port == "" || user == "" || pass == "" || from == "" {
		return errors.New("email provider config missing")
	}
	addr := fmt.Sprintf("%s:%s", host, port)
	subject := "[Security Event] " + event
	body, _ := json.MarshalIndent(details, "", "  ")
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", recipients[0], subject, string(body)))
	auth := smtp.PlainAuth("", user, pass, host)
	return smtp.SendMail(addr, auth, from, recipients, msg)
}

func sendSMSProvider(provider string, recipients []string, event string, details map[string]interface{}) error {
	enabled, ok := smsEnabled[provider]
	if !ok || !enabled {
		return nil
	}
	cfg := smsConfig[provider]
	twilioSID := cfg["sid"]
	twilioToken := cfg["token"]
	twilioFrom := cfg["from"]
	if twilioSID == "" || twilioToken == "" || twilioFrom == "" {
		return errors.New("sms provider config missing")
	}
	body, _ := json.Marshal(details)
	for _, to := range recipients {
		url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", twilioSID)
		data := fmt.Sprintf("From=%s&To=%s&Body=%s", twilioFrom, to, event+": "+string(body))
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

func sendChatProvider(provider string, recipients []string, event string, details map[string]interface{}) error {
	_ = recipients
	enabled, ok := chatEnabled[provider]
	if !ok || !enabled {
		return nil
	}
	cfg := chatConfig[provider]
	switch provider {
	case "slack":
		webhook := cfg["webhook"]
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
	case "teams":
		return errors.New("teams not implemented")
	default:
		return errors.New("unknown chat provider")
	}
}

func toPrettyJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// --- SecurityModuleConfigService ---

func (s *PostgresStore) GetSecurityModuleConfig(ctx context.Context, tenantID string) (SecurityModuleConfig, error) {
	const q = `SELECT enabled FROM security_module_configs WHERE tenant_id = $1`
	row := s.db.QueryRow(ctx, q, tenantID)
	var cfg SecurityModuleConfig
	if err := row.Scan(&cfg.Enabled); err != nil {
		s.logger.Error("GetSecurityModuleConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SecurityModuleConfig{}, err
	}
	return cfg, nil
}

func (s *PostgresStore) SetSecurityModuleConfig(ctx context.Context, tenantID string, enabled bool) error {
	const q = `INSERT INTO security_module_configs (tenant_id, enabled) VALUES ($1, $2)
	ON CONFLICT (tenant_id) DO UPDATE SET enabled = $2`
	_, err := s.db.Exec(ctx, q, tenantID, enabled)
	if err != nil {
		s.logger.Error("SetSecurityModuleConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return err
	}
	return nil
}

// --- SecurityEventWebhookService Postgres Implementation ---

func (s *PostgresStore) CreateWebhook(ctx context.Context, webhook SecurityEventWebhook) (SecurityEventWebhook, error) {
	if webhook.TenantID == "" || webhook.URL == "" || len(webhook.EventTypes) == 0 || webhook.Secret == "" {
		return SecurityEventWebhook{}, errors.New("missing required fields")
	}
	webhook.ID = generateUUID()
	webhook.Status = "active"
	webhook.CreatedAt = time.Now().UTC()
	webhook.UpdatedAt = webhook.CreatedAt
	etypes, _ := json.Marshal(webhook.EventTypes)
	const q = `INSERT INTO security_event_webhooks (id, tenant_id, url, event_types, secret, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	_, err := s.db.Exec(ctx, q, webhook.ID, webhook.TenantID, webhook.URL, string(etypes), webhook.Secret, webhook.Status, webhook.CreatedAt, webhook.UpdatedAt)
	if err != nil {
		s.logger.Error("CreateWebhook failed", logger.ErrorField(err))
		return SecurityEventWebhook{}, errors.New("failed to create webhook")
	}
	return webhook, nil
}

func (s *PostgresStore) ListWebhooks(ctx context.Context, tenantID string) ([]SecurityEventWebhook, error) {
	if tenantID == "" {
		return nil, errors.New("tenant_id required")
	}
	const q = `SELECT id, url, event_types, secret, status, created_at, updated_at FROM security_event_webhooks WHERE tenant_id = $1 AND status = 'active'`
	rows, err := s.db.Query(ctx, q, tenantID)
	if err != nil {
		s.logger.Error("ListWebhooks query failed", logger.ErrorField(err))
		return nil, errors.New("failed to list webhooks")
	}
	defer rows.Close()
	var out []SecurityEventWebhook
	for rows.Next() {
		var w SecurityEventWebhook
		var etypes string
		if err := rows.Scan(&w.ID, &w.URL, &etypes, &w.Secret, &w.Status, &w.CreatedAt, &w.UpdatedAt); err != nil {
			s.logger.Error("ListWebhooks scan failed", logger.ErrorField(err))
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
	_, err := s.db.Exec(ctx, q, time.Now().UTC(), id, tenantID)
	if err != nil {
		s.logger.Error("DeleteWebhook failed", logger.ErrorField(err))
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
	err := s.db.QueryRow(ctx, q, id, tenantID).Scan(&url, &secret, &status)
	if err != nil {
		s.logger.Error("TriggerWebhook lookup failed", logger.ErrorField(err))
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
		s.logger.Error("TriggerWebhook delivery failed", logger.ErrorField(err))
		return errors.New("webhook delivery failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("TriggerWebhook non-2xx", logger.String("status", resp.Status))
		return errors.New("webhook delivery non-2xx")
	}
	return nil
}

// generateUUID returns a new RFC4122 UUID string
func generateUUID() string {
	return "" // implement with github.com/google/uuid or similar in real code
}

// --- PasswordResetTokenService Postgres Implementation ---

func (s *PostgresStore) CreateToken(ctx context.Context, userID string, expiresIn time.Duration) (PasswordResetToken, error) {
	if userID == "" || expiresIn <= 0 {
		return PasswordResetToken{}, errors.New("user_id and expiresIn required")
	}
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return PasswordResetToken{}, errors.New("failed to generate token")
	}
	token := base64.URLEncoding.EncodeToString(b)
	t := PasswordResetToken{
		ID:        generateUUID(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(expiresIn).UTC(),
		Used:      false,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	const q = `INSERT INTO password_reset_tokens (id, user_id, token, expires_at, used, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`
	_, err = s.db.Exec(ctx, q, t.ID, t.UserID, t.Token, t.ExpiresAt, t.Used, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		s.logger.Error("CreateToken failed", logger.ErrorField(err))
		return PasswordResetToken{}, errors.New("failed to create token")
	}
	return t, nil
}

func (s *PostgresStore) VerifyToken(ctx context.Context, token string) (PasswordResetToken, error) {
	if token == "" {
		return PasswordResetToken{}, errors.New("token required")
	}
	const q = `SELECT id, user_id, token, expires_at, used, created_at, updated_at FROM password_reset_tokens WHERE token = $1`
	var t PasswordResetToken
	var used bool
	err := s.db.QueryRow(ctx, q, token).Scan(&t.ID, &t.UserID, &t.Token, &t.ExpiresAt, &used, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		s.logger.Error("VerifyToken lookup failed", logger.ErrorField(err))
		return PasswordResetToken{}, errors.New("token not found")
	}
	if used {
		return PasswordResetToken{}, errors.New("token already used")
	}
	if time.Now().After(t.ExpiresAt) {
		return PasswordResetToken{}, errors.New("token expired")
	}
	t.Used = used
	return t, nil
}

func (s *PostgresStore) UseToken(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("token required")
	}
	const q = `UPDATE password_reset_tokens SET used = TRUE, updated_at = $1 WHERE token = $2 AND used = FALSE AND expires_at > NOW()`
	res, err := s.db.Exec(ctx, q, time.Now().UTC(), token)
	if err != nil {
		s.logger.Error("UseToken update failed", logger.ErrorField(err))
		return errors.New("failed to use token")
	}
	n := res.RowsAffected()
	if n == 0 {
		return errors.New("token not valid or already used")
	}
	return nil
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
		id = generateUUID()
	}
	row := s.db.QueryRow(ctx, upsert, id, cfg.Scope, cfg.ScopeID, cfg.Limit, cfg.WindowSeconds)
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
	row := s.db.QueryRow(ctx, q, scope, scopeID)
	var cfg RateLimitConfig
	if err := row.Scan(&cfg.ID, &cfg.Scope, &cfg.ScopeID, &cfg.Limit, &cfg.WindowSeconds, &cfg.CreatedAt, &cfg.UpdatedAt); err != nil {
		return RateLimitConfig{}, errors.New("rate limit not found")
	}
	return cfg, nil
}

func (s *PostgresStore) DeleteRateLimit(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("id required")
	}
	const q = `DELETE FROM rate_limits WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	if err != nil {
		return errors.New("failed to delete rate limit")
	}
	return nil
}
