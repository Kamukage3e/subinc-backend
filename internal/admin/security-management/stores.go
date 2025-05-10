package security_management

import (
	"context"

	"errors"

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
