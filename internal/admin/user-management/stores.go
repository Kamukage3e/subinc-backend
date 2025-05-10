package user_management

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type PostgresStore struct {
	DB *pgxpool.Pool
}

// UserService
func (s *PostgresStore) CreateUser(ctx context.Context, user User) (User, error) {
	const q = `INSERT INTO users (id, email, password, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, status, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, user.ID, user.Email, user.Password, user.Status, user.CreatedAt, user.UpdatedAt)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
		logger.LogError("failed to create user", logger.ErrorField(err), logger.String("email", user.Email))
		return User{}, errors.New("failed to create user: " + err.Error())
	}
	return u, nil
}

func (s *PostgresStore) UpdateUser(ctx context.Context, user User) (User, error) {
	const q = `UPDATE users SET email=$1, status=$2, updated_at=$3 WHERE id=$4 RETURNING id, email, status, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, user.Email, user.Status, user.UpdatedAt, user.ID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
		logger.LogError("failed to update user", logger.ErrorField(err), logger.String("id", user.ID))
		return User{}, errors.New("failed to update user: " + err.Error())
	}
	return u, nil
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	const q = `DELETE FROM users WHERE id=$1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete user", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete user: " + err.Error())
	}
	return nil
}

func (s *PostgresStore) GetUser(ctx context.Context, id string) (User, error) {
	const q = `SELECT id, email, status, created_at, updated_at FROM users WHERE id=$1`
	row := s.DB.QueryRow(ctx, q, id)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
		logger.LogError("failed to get user", logger.ErrorField(err), logger.String("id", id))
		return User{}, errors.New("failed to get user: " + err.Error())
	}
	return u, nil
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (User, error) {
	const q = `SELECT id, email, status, created_at, updated_at FROM users WHERE email=$1`
	row := s.DB.QueryRow(ctx, q, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
		logger.LogError("failed to get user by email", logger.ErrorField(err), logger.String("email", email))
		return User{}, errors.New("failed to get user by email: " + err.Error())
	}
	return u, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context, status string, page, pageSize int) ([]User, error) {
	const q = `SELECT id, email, status, created_at, updated_at FROM users WHERE status=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := s.DB.Query(ctx, q, status, pageSize, (page-1)*pageSize)
	if err != nil {
		logger.LogError("failed to list users", logger.ErrorField(err))
		return nil, errors.New("failed to list users: " + err.Error())
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
			logger.LogError("failed to scan user row", logger.ErrorField(err))
			return nil, errors.New("failed to scan user row: " + err.Error())
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating user rows", logger.ErrorField(err))
		return nil, errors.New("error iterating user rows: " + err.Error())
	}
	return users, nil
}

// UserProfileService
func (s *PostgresStore) CreateProfile(ctx context.Context, profile UserProfile) (UserProfile, error) {
	const q = `INSERT INTO user_profiles (user_id, full_name, avatar_url, bio, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id, full_name, avatar_url, bio, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, profile.UserID, profile.FullName, profile.AvatarURL, profile.Bio, profile.CreatedAt, profile.UpdatedAt)
	var p UserProfile
	if err := row.Scan(&p.UserID, &p.FullName, &p.AvatarURL, &p.Bio, &p.CreatedAt, &p.UpdatedAt); err != nil {
		logger.LogError("failed to create user profile", logger.ErrorField(err), logger.String("user_id", profile.UserID))
		return UserProfile{}, errors.New("failed to create user profile: " + err.Error())
	}
	return p, nil
}

func (s *PostgresStore) UpdateProfile(ctx context.Context, profile UserProfile) (UserProfile, error) {
	const q = `UPDATE user_profiles SET full_name=$1, avatar_url=$2, bio=$3, updated_at=$4 WHERE user_id=$5 RETURNING user_id, full_name, avatar_url, bio, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, profile.FullName, profile.AvatarURL, profile.Bio, profile.UpdatedAt, profile.UserID)
	var p UserProfile
	if err := row.Scan(&p.UserID, &p.FullName, &p.AvatarURL, &p.Bio, &p.CreatedAt, &p.UpdatedAt); err != nil {
		logger.LogError("failed to update user profile", logger.ErrorField(err), logger.String("user_id", profile.UserID))
		return UserProfile{}, errors.New("failed to update user profile: " + err.Error())
	}
	return p, nil
}

func (s *PostgresStore) GetProfile(ctx context.Context, userID string) (UserProfile, error) {
	const q = `SELECT user_id, full_name, avatar_url, bio, created_at, updated_at FROM user_profiles WHERE user_id=$1`
	row := s.DB.QueryRow(ctx, q, userID)
	var p UserProfile
	if err := row.Scan(&p.UserID, &p.FullName, &p.AvatarURL, &p.Bio, &p.CreatedAt, &p.UpdatedAt); err != nil {
		logger.LogError("failed to get user profile", logger.ErrorField(err), logger.String("user_id", userID))
		return UserProfile{}, errors.New("failed to get user profile: " + err.Error())
	}
	return p, nil
}

// UserSettingsService
func (s *PostgresStore) GetSettings(ctx context.Context, userID string) (UserSettings, error) {
	const q = `SELECT user_id, settings, updated_at FROM user_settings WHERE user_id=$1`
	row := s.DB.QueryRow(ctx, q, userID)
	var sng UserSettings
	if err := row.Scan(&sng.UserID, &sng.Settings, &sng.UpdatedAt); err != nil {
		logger.LogError("failed to get user settings", logger.ErrorField(err), logger.String("user_id", userID))
		return UserSettings{}, errors.New("failed to get user settings: " + err.Error())
	}
	return sng, nil
}

func (s *PostgresStore) UpdateSettings(ctx context.Context, userID, settings string) error {
	const q = `UPDATE user_settings SET settings=$1, updated_at=now() WHERE user_id=$2`
	_, err := s.DB.Exec(ctx, q, settings, userID)
	if err != nil {
		logger.LogError("failed to update user settings", logger.ErrorField(err), logger.String("user_id", userID))
		return errors.New("failed to update user settings: " + err.Error())
	}
	return nil
}

// UserSessionService
func (s *PostgresStore) CreateSession(ctx context.Context, session UserSession) (UserSession, error) {
	const q = `INSERT INTO user_sessions (id, user_id, ip, user_agent, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, user_id, ip, user_agent, expires_at, created_at`
	row := s.DB.QueryRow(ctx, q, session.ID, session.UserID, session.IP, session.UserAgent, session.ExpiresAt, session.CreatedAt)
	var sss UserSession
	if err := row.Scan(&sss.ID, &sss.UserID, &sss.IP, &sss.UserAgent, &sss.ExpiresAt, &sss.CreatedAt); err != nil {
		logger.LogError("failed to create user session", logger.ErrorField(err), logger.String("user_id", session.UserID))
		return UserSession{}, errors.New("failed to create user session: " + err.Error())
	}
	return sss, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, id string) error {
	const q = `DELETE FROM user_sessions WHERE id=$1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("failed to delete user session", logger.ErrorField(err), logger.String("id", id))
		return errors.New("failed to delete user session: " + err.Error())
	}
	return nil
}

func (s *PostgresStore) GetSession(ctx context.Context, id string) (UserSession, error) {
	const q = `SELECT id, user_id, ip, user_agent, expires_at, created_at FROM user_sessions WHERE id=$1`
	row := s.DB.QueryRow(ctx, q, id)
	var sss UserSession
	if err := row.Scan(&sss.ID, &sss.UserID, &sss.IP, &sss.UserAgent, &sss.ExpiresAt, &sss.CreatedAt); err != nil {
		logger.LogError("failed to get user session", logger.ErrorField(err), logger.String("id", id))
		return UserSession{}, errors.New("failed to get user session: " + err.Error())
	}
	return sss, nil
}

func (s *PostgresStore) ListSessions(ctx context.Context, userID string, page, pageSize int) ([]UserSession, error) {
	const q = `SELECT id, user_id, ip, user_agent, expires_at, created_at FROM user_sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := s.DB.Query(ctx, q, userID, pageSize, (page-1)*pageSize)
	if err != nil {
		logger.LogError("failed to list user sessions", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, errors.New("failed to list user sessions: " + err.Error())
	}
	defer rows.Close()
	var sessions []UserSession
	for rows.Next() {
		var sss UserSession
		if err := rows.Scan(&sss.ID, &sss.UserID, &sss.IP, &sss.UserAgent, &sss.ExpiresAt, &sss.CreatedAt); err != nil {
			logger.LogError("failed to scan user session row", logger.ErrorField(err))
			return nil, errors.New("failed to scan user session row: " + err.Error())
		}
		sessions = append(sessions, sss)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating user session rows", logger.ErrorField(err))
		return nil, errors.New("error iterating user session rows: " + err.Error())
	}
	return sessions, nil
}

// UserAuditLogService
func (s *PostgresStore) CreateAuditLog(ctx context.Context, log UserAuditLog) (UserAuditLog, error) {
	const q = `INSERT INTO user_audit_logs (id, user_id, actor_id, action, target_id, details, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, user_id, actor_id, action, target_id, details, created_at`
	row := s.DB.QueryRow(ctx, q, log.ID, log.UserID, log.ActorID, log.Action, log.TargetID, log.Details, log.CreatedAt)
	var l UserAuditLog
	if err := row.Scan(&l.ID, &l.UserID, &l.ActorID, &l.Action, &l.TargetID, &l.Details, &l.CreatedAt); err != nil {
		logger.LogError("failed to create user audit log", logger.ErrorField(err), logger.String("user_id", log.UserID))
		return UserAuditLog{}, errors.New("failed to create user audit log: " + err.Error())
	}
	return l, nil
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, userID, actorID, action string, page, pageSize int) ([]UserAuditLog, error) {
	const q = `SELECT id, user_id, actor_id, action, target_id, details, created_at FROM user_audit_logs WHERE user_id=$1 AND actor_id=$2 AND action=$3 ORDER BY created_at DESC LIMIT $4 OFFSET $5`
	rows, err := s.DB.Query(ctx, q, userID, actorID, action, pageSize, (page-1)*pageSize)
	if err != nil {
		logger.LogError("failed to list user audit logs", logger.ErrorField(err), logger.String("user_id", userID))
		return nil, errors.New("failed to list user audit logs: " + err.Error())
	}
	defer rows.Close()
	var logs []UserAuditLog
	for rows.Next() {
		var l UserAuditLog
		if err := rows.Scan(&l.ID, &l.UserID, &l.ActorID, &l.Action, &l.TargetID, &l.Details, &l.CreatedAt); err != nil {
			logger.LogError("failed to scan user audit log row", logger.ErrorField(err))
			return nil, errors.New("failed to scan user audit log row: " + err.Error())
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("error iterating user audit log rows", logger.ErrorField(err))
		return nil, errors.New("error iterating user audit log rows: " + err.Error())
	}
	return logs, nil
}
