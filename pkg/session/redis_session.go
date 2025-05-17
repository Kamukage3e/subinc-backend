package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/subinc/subinc-backend/internal/pkg/interfaces"
	. "github.com/subinc/subinc-backend/internal/pkg/logger"
)

const (
	// DefaultSessionTTL defines the default session lifetime
	DefaultSessionTTL = 24 * time.Hour

	// SessionIDLength for generating secure session IDs
	SessionIDLength = 32

	// MaxSessionDataSize defines the maximum session data size in bytes
	MaxSessionDataSize = 4096
)

var (
	// ErrSessionNotFound indicates the session does not exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionInvalid indicates the session is corrupted or tampered
	ErrSessionInvalid = errors.New("session invalid or corrupted")

	// ErrSessionExpired indicates the session has expired
	ErrSessionExpired = errors.New("session expired")

	// ErrDataTooLarge indicates the session data exceeds the maximum allowed size
	ErrDataTooLarge = errors.New("session data too large")

	// Session metrics for Prometheus
	sessionOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_session_operations_total",
			Help: "Total number of Redis session operations",
		},
		[]string{"operation", "status"},
	)

	sessionSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_session_size_bytes",
			Help:    "Size of session data in bytes",
			Buckets: []float64{128, 512, 1024, 2048, 4096, 8192},
		},
		[]string{"operation"},
	)

	sessionOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_session_operation_duration_seconds",
			Help:    "Duration of Redis session operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "redis_active_sessions",
			Help: "Number of active sessions",
		},
	)
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(sessionOperations)
	prometheus.MustRegister(sessionSize)
	prometheus.MustRegister(sessionOperationDuration)
	prometheus.MustRegister(activeSessions)
}

// SessionManager handles Redis-backed sessions with secure defaults
// and implements the interfaces.SessionService interface
type SessionManager struct {
	client     *redis.Client
	logger     *Logger
	prefix     string
	defaultTTL time.Duration
}

// NewSessionManager creates a new secure session manager
func NewSessionManager(client *redis.Client, logger *Logger, prefix string) (*SessionManager, error) {
	if client == nil {
		return nil, errors.New("redis client cannot be nil")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}
	if prefix == "" {
		prefix = "session"
	}
	return &SessionManager{
		client:     client,
		logger:     logger,
		prefix:     prefix,
		defaultTTL: DefaultSessionTTL,
	}, nil
}

// SetDefaultTTL changes the default session TTL
func (m *SessionManager) SetDefaultTTL(ttl time.Duration) {
	if ttl < time.Minute {
		m.logger.Warn("Session TTL too short, using minimum of 1 minute",
			Duration("requested_ttl", ttl),
			Duration("minimum_ttl", time.Minute),
		)
		ttl = time.Minute
	}
	m.defaultTTL = ttl
}

// formattedKey creates a Redis key with prefix for session storage
func (m *SessionManager) formattedKey(sessionID string) string {
	return fmt.Sprintf("%s:%s", m.prefix, sessionID)
}

// GenerateID creates a cryptographically secure session ID
func (m *SessionManager) GenerateID() (string, error) {
	bytes := make([]byte, SessionIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure session ID: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// CreateSession starts a new session for the given user and tenant
func (m *SessionManager) CreateSession(ctx context.Context, userID, tenantID string, data map[string]interface{}) (interfaces.Session, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("create").Observe(time.Since(startTime).Seconds())
	}()

	// Generate a secure random session ID
	sessionID, err := m.GenerateID()
	if err != nil {
		m.logger.Error("Failed to generate session ID",
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("create", "error").Inc()
		return interfaces.Session{}, err
	}

	// Create a new session
	now := time.Now().UTC()
	session := interfaces.Session{
		ID:           sessionID,
		UserID:       userID,
		TenantID:     tenantID,
		Data:         data,
		CreatedAt:    now,
		LastAccessAt: now,
		ExpiresAt:    now.Add(m.defaultTTL),
	}

	// Validate data size
	jsonData, err := json.Marshal(session)
	if err != nil {
		m.logger.Error("Failed to marshal session data",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("create", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to marshal session data: %w", err)
	}

	if len(jsonData) > MaxSessionDataSize {
		m.logger.Warn("Session data too large",
			String("session_id", sessionID),
			Int("data_size", len(jsonData)),
			Int("max_size", MaxSessionDataSize),
		)
		sessionOperations.WithLabelValues("create", "data_too_large").Inc()
		return interfaces.Session{}, ErrDataTooLarge
	}

	// Store in Redis
	key := m.formattedKey(sessionID)
	err = m.client.Set(ctx, key, jsonData, m.defaultTTL).Err()
	if err != nil {
		m.logger.Error("Failed to store session in Redis",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("create", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to store session: %w", err)
	}

	m.logger.Debug("Session created",
		String("session_id", sessionID),
		String("user_id", userID),
		String("tenant_id", tenantID),
		Time("expires_at", session.ExpiresAt),
	)

	sessionOperations.WithLabelValues("create", "success").Inc()
	sessionSize.WithLabelValues("create").Observe(float64(len(jsonData)))
	activeSessions.Inc()

	return session, nil
}

// GetSession retrieves a session by ID, extending its expiration
func (m *SessionManager) GetSession(ctx context.Context, sessionID string) (interfaces.Session, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("get").Observe(time.Since(startTime).Seconds())
	}()

	key := m.formattedKey(sessionID)
	jsonData, err := m.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			sessionOperations.WithLabelValues("get", "not_found").Inc()
			return interfaces.Session{}, ErrSessionNotFound
		}

		m.logger.Error("Failed to retrieve session from Redis",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("get", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to retrieve session: %w", err)
	}

	var session interfaces.Session
	if err := json.Unmarshal(jsonData, &session); err != nil {
		m.logger.Error("Failed to unmarshal session data",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("get", "error").Inc()
		return interfaces.Session{}, ErrSessionInvalid
	}

	// Update last access time and extend expiration
	now := time.Now().UTC()
	session.LastAccessAt = now
	session.ExpiresAt = now.Add(m.defaultTTL)

	// Store the updated session
	updatedData, err := json.Marshal(session)
	if err != nil {
		m.logger.Error("Failed to marshal updated session data",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("get", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	// Extend expiration
	err = m.client.Set(ctx, key, updatedData, m.defaultTTL).Err()
	if err != nil {
		m.logger.Error("Failed to extend session expiration",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("get", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to extend session: %w", err)
	}

	sessionOperations.WithLabelValues("get", "success").Inc()
	sessionSize.WithLabelValues("get").Observe(float64(len(jsonData)))
	return session, nil
}

// RefreshSession extends a session's lifetime
func (m *SessionManager) RefreshSession(ctx context.Context, sessionID string) (interfaces.Session, error) {
	return m.GetSession(ctx, sessionID) // GetSession already refreshes the session
}

// DeleteSession removes a session
func (m *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("delete").Observe(time.Since(startTime).Seconds())
	}()

	key := m.formattedKey(sessionID)
	deleted, err := m.client.Del(ctx, key).Result()
	if err != nil {
		m.logger.Error("Failed to delete session",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("delete", "error").Inc()
		return fmt.Errorf("failed to delete session: %w", err)
	}

	if deleted > 0 {
		activeSessions.Dec()
		sessionOperations.WithLabelValues("delete", "success").Inc()
		m.logger.Debug("Session deleted", String("session_id", sessionID))
	} else {
		sessionOperations.WithLabelValues("delete", "not_found").Inc()
		return ErrSessionNotFound
	}

	return nil
}

// UpdateSession updates session data while preserving the session ID and metadata
func (m *SessionManager) UpdateSession(ctx context.Context, sessionID string, data map[string]interface{}) (interfaces.Session, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("update").Observe(time.Since(startTime).Seconds())
	}()

	// Get the existing session
	key := m.formattedKey(sessionID)
	jsonData, err := m.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			sessionOperations.WithLabelValues("update", "not_found").Inc()
			return interfaces.Session{}, ErrSessionNotFound
		}

		m.logger.Error("Failed to retrieve session for update",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("update", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to retrieve session for update: %w", err)
	}

	// Unmarshal the session
	var session interfaces.Session
	if err := json.Unmarshal(jsonData, &session); err != nil {
		m.logger.Error("Failed to unmarshal session data for update",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("update", "error").Inc()
		return interfaces.Session{}, ErrSessionInvalid
	}

	// Update session data
	session.Data = data
	session.LastAccessAt = time.Now().UTC()

	// Validate data size
	updatedData, err := json.Marshal(session)
	if err != nil {
		m.logger.Error("Failed to marshal updated session data",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("update", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	if len(updatedData) > MaxSessionDataSize {
		m.logger.Warn("Updated session data too large",
			String("session_id", sessionID),
			Int("data_size", len(updatedData)),
			Int("max_size", MaxSessionDataSize),
		)
		sessionOperations.WithLabelValues("update", "data_too_large").Inc()
		return interfaces.Session{}, ErrDataTooLarge
	}

	// Store the updated session
	err = m.client.Set(ctx, key, updatedData, m.defaultTTL).Err()
	if err != nil {
		m.logger.Error("Failed to store updated session",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("update", "error").Inc()
		return interfaces.Session{}, fmt.Errorf("failed to update session: %w", err)
	}

	sessionOperations.WithLabelValues("update", "success").Inc()
	sessionSize.WithLabelValues("update").Observe(float64(len(updatedData)))
	return session, nil
}

// ListUserSessions gets all sessions for a user
func (m *SessionManager) ListUserSessions(ctx context.Context, userID string) ([]interfaces.Session, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("list_user").Observe(time.Since(startTime).Seconds())
	}()

	// Scan all keys with the session prefix
	pattern := m.formattedKey("*")
	var sessions []interfaces.Session
	var cursor uint64
	var keys []string

	for {
		var batch []string
		var err error
		batch, cursor, err = m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			m.logger.Error("Failed to scan sessions",
				String("user_id", userID),
				ErrorField(err),
			)
			sessionOperations.WithLabelValues("list_user", "error").Inc()
			return nil, fmt.Errorf("failed to scan sessions: %w", err)
		}

		keys = append(keys, batch...)

		if cursor == 0 {
			break
		}
	}

	// No sessions found
	if len(keys) == 0 {
		sessionOperations.WithLabelValues("list_user", "not_found").Inc()
		return []interfaces.Session{}, nil
	}

	// Get session data for each key
	for _, key := range keys {
		jsonData, err := m.client.Get(ctx, key).Bytes()
		if err != nil {
			if err == redis.Nil {
				continue // Skip if the session was deleted between scan and get
			}

			m.logger.Error("Failed to retrieve session during list",
				String("key", key),
				String("user_id", userID),
				ErrorField(err),
			)
			continue
		}

		var session interfaces.Session
		if err := json.Unmarshal(jsonData, &session); err != nil {
			m.logger.Error("Failed to unmarshal session during list",
				String("key", key),
				ErrorField(err),
			)
			continue
		}

		// Only add sessions for the requested user
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}

	sessionOperations.WithLabelValues("list_user", "success").Inc()
	return sessions, nil
}

// DeleteUserSessions removes all sessions for a user
func (m *SessionManager) DeleteUserSessions(ctx context.Context, userID string) (int, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("delete_user").Observe(time.Since(startTime).Seconds())
	}()

	sessions, err := m.ListUserSessions(ctx, userID)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, session := range sessions {
		if err := m.DeleteSession(ctx, session.ID); err != nil {
			m.logger.Warn("Failed to delete user session",
				String("user_id", userID),
				String("session_id", session.ID),
				ErrorField(err),
			)
			continue
		}
		count++
	}

	sessionOperations.WithLabelValues("delete_user", "success").Inc()
	return count, nil
}

// DeleteTenantSessions removes all sessions for a tenant
func (m *SessionManager) DeleteTenantSessions(ctx context.Context, tenantID string) (int, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("delete_tenant").Observe(time.Since(startTime).Seconds())
	}()

	// Scan all keys with the session prefix
	pattern := m.formattedKey("*")
	var count int
	var cursor uint64

	for {
		var batch []string
		var err error
		batch, cursor, err = m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			m.logger.Error("Failed to scan sessions for tenant deletion",
				String("tenant_id", tenantID),
				ErrorField(err),
			)
			sessionOperations.WithLabelValues("delete_tenant", "error").Inc()
			return count, fmt.Errorf("failed to scan sessions: %w", err)
		}

		for _, key := range batch {
			jsonData, err := m.client.Get(ctx, key).Bytes()
			if err != nil {
				if err == redis.Nil {
					continue // Skip if the session was deleted between scan and get
				}
				m.logger.Error("Failed to retrieve session during tenant deletion",
					String("key", key),
					String("tenant_id", tenantID),
					ErrorField(err),
				)
				continue
			}

			var session interfaces.Session
			if err := json.Unmarshal(jsonData, &session); err != nil {
				m.logger.Error("Failed to unmarshal session during tenant deletion",
					String("key", key),
					ErrorField(err),
				)
				continue
			}

			// Delete if it belongs to the specified tenant
			if session.TenantID == tenantID {
				deleted, err := m.client.Del(ctx, key).Result()
				if err != nil {
					m.logger.Error("Failed to delete tenant session",
						String("tenant_id", tenantID),
						String("session_id", session.ID),
						ErrorField(err),
					)
					continue
				}

				if deleted > 0 {
					count++
					activeSessions.Dec()
				}
			}
		}

		if cursor == 0 {
			break
		}
	}

	sessionOperations.WithLabelValues("delete_tenant", "success").Inc()
	return count, nil
}

// GetActiveSessionCount returns the number of active sessions
func (m *SessionManager) GetActiveSessionCount(ctx context.Context) (int64, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("count").Observe(time.Since(startTime).Seconds())
	}()

	pattern := m.formattedKey("*")
	count, err := m.client.Keys(ctx, pattern).Result()
	if err != nil {
		m.logger.Error("Failed to count sessions",
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("count", "error").Inc()
		return 0, fmt.Errorf("failed to count sessions: %w", err)
	}

	sessionOperations.WithLabelValues("count", "success").Inc()
	return int64(len(count)), nil
}

// CleanExpiredSessions removes all expired sessions
func (m *SessionManager) CleanExpiredSessions(ctx context.Context) (int, error) {
	// Note: Redis automatically removes expired keys,
	// but this can be useful for manual cleanup of orphaned sessions
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("cleanup").Observe(time.Since(startTime).Seconds())
	}()

	// Since Redis handles expiration, this is a no-op but reported for API completeness
	sessionOperations.WithLabelValues("cleanup", "success").Inc()
	return 0, nil
}
