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

// Session represents user session data
type Session struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	TenantID     string                 `json:"tenant_id"`
	Data         map[string]interface{} `json:"data"`
	CreatedAt    time.Time              `json:"created_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	LastAccessAt time.Time              `json:"last_access_at"`
}

// SessionManager handles Redis-backed sessions with secure defaults
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

// Create starts a new session for the given user and tenant
func (m *SessionManager) Create(ctx context.Context, userID, tenantID string, data map[string]interface{}) (*Session, error) {
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
		return nil, err
	}

	// Create a new session
	session := &Session{
		ID:           sessionID,
		UserID:       userID,
		TenantID:     tenantID,
		Data:         data,
		CreatedAt:    time.Now().UTC(),
		LastAccessAt: time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(m.defaultTTL),
	}

	// Validate data size
	jsonData, err := json.Marshal(session)
	if err != nil {
		m.logger.Error("Failed to marshal session data",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("create", "error").Inc()
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	if len(jsonData) > MaxSessionDataSize {
		m.logger.Warn("Session data too large",
			String("session_id", sessionID),
			Int("data_size", len(jsonData)),
			Int("max_size", MaxSessionDataSize),
		)
		sessionOperations.WithLabelValues("create", "data_too_large").Inc()
		return nil, ErrDataTooLarge
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
		return nil, fmt.Errorf("failed to store session: %w", err)
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

// Get retrieves a session by ID, extending its expiration
func (m *SessionManager) Get(ctx context.Context, sessionID string, extend bool) (*Session, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("get").Observe(time.Since(startTime).Seconds())
	}()

	key := m.formattedKey(sessionID)
	jsonData, err := m.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			sessionOperations.WithLabelValues("get", "not_found").Inc()
			return nil, ErrSessionNotFound
		}

		m.logger.Error("Failed to retrieve session from Redis",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("get", "error").Inc()
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(jsonData, &session); err != nil {
		m.logger.Error("Failed to unmarshal session data",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("get", "invalid_data").Inc()
		return nil, ErrSessionInvalid
	}

	// Check if session has expired
	if time.Now().UTC().After(session.ExpiresAt) {
		m.logger.Debug("Session expired",
			String("session_id", sessionID),
			Time("expired_at", session.ExpiresAt),
		)

		// Delete expired session
		m.client.Del(ctx, key)
		activeSessions.Dec()

		sessionOperations.WithLabelValues("get", "expired").Inc()
		return nil, ErrSessionExpired
	}

	// Update last access time and extend expiration if requested
	if extend {
		session.LastAccessAt = time.Now().UTC()
		session.ExpiresAt = time.Now().UTC().Add(m.defaultTTL)

		// Save updated session back to Redis
		updatedData, err := json.Marshal(session)
		if err != nil {
			m.logger.Error("Failed to marshal updated session data",
				String("session_id", sessionID),
				ErrorField(err),
			)
			sessionOperations.WithLabelValues("get", "error").Inc()
			return &session, nil // Return the session anyway but don't extend
		}

		if err := m.client.Set(ctx, key, updatedData, m.defaultTTL).Err(); err != nil {
			m.logger.Error("Failed to extend session in Redis",
				String("session_id", sessionID),
				ErrorField(err),
			)
			sessionOperations.WithLabelValues("get", "error").Inc()
			return &session, nil // Return the session anyway but don't extend
		}

		m.logger.Debug("Session extended",
			String("session_id", sessionID),
			Time("expires_at", session.ExpiresAt),
		)
	}

	m.logger.Debug("Session retrieved",
		String("session_id", sessionID),
		String("user_id", session.UserID),
	)

	sessionOperations.WithLabelValues("get", "success").Inc()
	sessionSize.WithLabelValues("get").Observe(float64(len(jsonData)))
	return &session, nil
}

// Update modifies a session's data
func (m *SessionManager) Update(ctx context.Context, sessionID string, data map[string]interface{}) (*Session, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("update").Observe(time.Since(startTime).Seconds())
	}()

	// First get the session
	session, err := m.Get(ctx, sessionID, false)
	if err != nil {
		sessionOperations.WithLabelValues("update", "get_failed").Inc()
		return nil, err
	}

	// Update the data
	session.Data = data
	session.LastAccessAt = time.Now().UTC()

	// Validate data size
	jsonData, err := json.Marshal(session)
	if err != nil {
		m.logger.Error("Failed to marshal updated session data",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("update", "error").Inc()
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	if len(jsonData) > MaxSessionDataSize {
		m.logger.Warn("Updated session data too large",
			String("session_id", sessionID),
			Int("data_size", len(jsonData)),
			Int("max_size", MaxSessionDataSize),
		)
		sessionOperations.WithLabelValues("update", "data_too_large").Inc()
		return nil, ErrDataTooLarge
	}

	// Store in Redis
	key := m.formattedKey(sessionID)
	remaining := time.Until(session.ExpiresAt)
	if remaining < time.Minute {
		remaining = m.defaultTTL // If almost expired, use default TTL
	}

	err = m.client.Set(ctx, key, jsonData, remaining).Err()
	if err != nil {
		m.logger.Error("Failed to store updated session in Redis",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("update", "error").Inc()
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	m.logger.Debug("Session updated",
		String("session_id", sessionID),
		Time("expires_at", session.ExpiresAt),
	)

	sessionOperations.WithLabelValues("update", "success").Inc()
	sessionSize.WithLabelValues("update").Observe(float64(len(jsonData)))

	return session, nil
}

// Delete removes a session
func (m *SessionManager) Delete(ctx context.Context, sessionID string) error {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("delete").Observe(time.Since(startTime).Seconds())
	}()

	key := m.formattedKey(sessionID)
	result, err := m.client.Del(ctx, key).Result()
	if err != nil {
		m.logger.Error("Failed to delete session from Redis",
			String("session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("delete", "error").Inc()
		return fmt.Errorf("failed to delete session: %w", err)
	}

	if result > 0 {
		activeSessions.Dec()
	}

	m.logger.Debug("Session deleted",
		String("session_id", sessionID),
		Any("deleted_count", result),
	)

	sessionOperations.WithLabelValues("delete", "success").Inc()
	return nil
}

// Rotate creates a new session with the same data but a new ID, and deletes the old session
func (m *SessionManager) Rotate(ctx context.Context, sessionID string) (*Session, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("rotate").Observe(time.Since(startTime).Seconds())
	}()

	// Get the existing session
	session, err := m.Get(ctx, sessionID, false)
	if err != nil {
		sessionOperations.WithLabelValues("rotate", "get_failed").Inc()
		return nil, err
	}

	// Create a new session with the same data but new ID
	newSessionID, err := m.GenerateID()
	if err != nil {
		m.logger.Error("Failed to generate new session ID for rotation",
			String("old_session_id", sessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("rotate", "error").Inc()
		return nil, err
	}

	newSession := &Session{
		ID:           newSessionID,
		UserID:       session.UserID,
		TenantID:     session.TenantID,
		Data:         session.Data,
		CreatedAt:    time.Now().UTC(),
		LastAccessAt: time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(m.defaultTTL),
	}

	// Store the new session
	jsonData, err := json.Marshal(newSession)
	if err != nil {
		m.logger.Error("Failed to marshal rotated session data",
			String("old_session_id", sessionID),
			String("new_session_id", newSessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("rotate", "error").Inc()
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	newKey := m.formattedKey(newSessionID)
	oldKey := m.formattedKey(sessionID)

	// Execute atomic transaction to store new session and delete old session
	pipe := m.client.Pipeline()
	pipe.Set(ctx, newKey, jsonData, m.defaultTTL)
	pipe.Del(ctx, oldKey)
	_, err = pipe.Exec(ctx)
	if err != nil {
		m.logger.Error("Failed to execute session rotation pipeline",
			String("old_session_id", sessionID),
			String("new_session_id", newSessionID),
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("rotate", "error").Inc()
		return nil, fmt.Errorf("failed to rotate session: %w", err)
	}

	m.logger.Debug("Session rotated",
		String("old_session_id", sessionID),
		String("new_session_id", newSessionID),
		String("user_id", newSession.UserID),
		Time("expires_at", newSession.ExpiresAt),
	)

	sessionOperations.WithLabelValues("rotate", "success").Inc()
	sessionSize.WithLabelValues("rotate").Observe(float64(len(jsonData)))

	return newSession, nil
}

// DeleteByUserID removes all sessions for a specific user
func (m *SessionManager) DeleteByUserID(ctx context.Context, userID string) (int, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("delete_by_user_id").Observe(time.Since(startTime).Seconds())
	}()

	// Unfortunately no direct way to query by user ID with Redis
	// We need to scan all session keys and check each one
	pattern := m.formattedKey("*")
	var deletedCount int
	var cursor uint64 = 0

	for {
		var keys []string
		var err error
		keys, cursor, err = m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			m.logger.Error("Failed to scan session keys",
				String("user_id", userID),
				ErrorField(err),
			)
			sessionOperations.WithLabelValues("delete_by_user_id", "error").Inc()
			return deletedCount, fmt.Errorf("failed to scan session keys: %w", err)
		}

		// Check each key we found
		if len(keys) > 0 {
			pipe := m.client.Pipeline()
			gets := make(map[string]*redis.StringCmd)

			for _, key := range keys {
				gets[key] = pipe.Get(ctx, key)
			}

			// Execute gets
			_, err = pipe.Exec(ctx)
			if err != nil && err != redis.Nil {
				m.logger.Error("Failed to get session data during user sessions deletion",
					String("user_id", userID),
					ErrorField(err),
				)
				// Continue with any keys we can read
			}

			// Check each session for matching user ID
			toDelete := make([]string, 0)
			for key, cmd := range gets {
				data, err := cmd.Bytes()
				if err != nil {
					continue // Skip invalid sessions
				}

				var session Session
				if err := json.Unmarshal(data, &session); err != nil {
					continue // Skip corrupted sessions
				}

				if session.UserID == userID {
					toDelete = append(toDelete, key)
				}
			}

			// Delete matching sessions
			if len(toDelete) > 0 {
				if err := m.client.Del(ctx, toDelete...).Err(); err != nil {
					m.logger.Error("Failed to delete user sessions",
						String("user_id", userID),
						Int("found_count", len(toDelete)),
						ErrorField(err),
					)
					sessionOperations.WithLabelValues("delete_by_user_id", "error").Inc()
				} else {
					deletedCount += len(toDelete)
					activeSessions.Sub(float64(len(toDelete)))
				}
			}
		}

		// Exit loop when we've scanned all keys
		if cursor == 0 {
			break
		}
	}

	m.logger.Info("User sessions deleted",
		String("user_id", userID),
		Int("deleted_count", deletedCount),
	)

	sessionOperations.WithLabelValues("delete_by_user_id", "success").Inc()
	return deletedCount, nil
}

// DeleteByTenantID removes all sessions for a specific tenant
func (m *SessionManager) DeleteByTenantID(ctx context.Context, tenantID string) (int, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("delete_by_tenant_id").Observe(time.Since(startTime).Seconds())
	}()

	// Unfortunately no direct way to query by tenant ID with Redis
	// We need to scan all session keys and check each one
	pattern := m.formattedKey("*")
	var deletedCount int
	var cursor uint64 = 0

	for {
		var keys []string
		var err error
		keys, cursor, err = m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			m.logger.Error("Failed to scan session keys for tenant",
				String("tenant_id", tenantID),
				ErrorField(err),
			)
			sessionOperations.WithLabelValues("delete_by_tenant_id", "error").Inc()
			return deletedCount, fmt.Errorf("failed to scan session keys: %w", err)
		}

		// Check each key we found
		if len(keys) > 0 {
			pipe := m.client.Pipeline()
			gets := make(map[string]*redis.StringCmd)

			for _, key := range keys {
				gets[key] = pipe.Get(ctx, key)
			}

			// Execute gets
			_, err = pipe.Exec(ctx)
			if err != nil && err != redis.Nil {
				m.logger.Error("Failed to get session data during tenant sessions deletion",
					String("tenant_id", tenantID),
					ErrorField(err),
				)
				// Continue with any keys we can read
			}

			// Check each session for matching tenant ID
			toDelete := make([]string, 0)
			for key, cmd := range gets {
				data, err := cmd.Bytes()
				if err != nil {
					continue // Skip invalid sessions
				}

				var session Session
				if err := json.Unmarshal(data, &session); err != nil {
					continue // Skip corrupted sessions
				}

				if session.TenantID == tenantID {
					toDelete = append(toDelete, key)
				}
			}

			// Delete matching sessions
			if len(toDelete) > 0 {
				if err := m.client.Del(ctx, toDelete...).Err(); err != nil {
					m.logger.Error("Failed to delete tenant sessions",
						String("tenant_id", tenantID),
						Int("found_count", len(toDelete)),
						ErrorField(err),
					)
					sessionOperations.WithLabelValues("delete_by_tenant_id", "error").Inc()
				} else {
					deletedCount += len(toDelete)
					activeSessions.Sub(float64(len(toDelete)))
				}
			}
		}

		// Exit loop when we've scanned all keys
		if cursor == 0 {
			break
		}
	}

	m.logger.Info("Tenant sessions deleted",
		String("tenant_id", tenantID),
		Int("deleted_count", deletedCount),
	)

	sessionOperations.WithLabelValues("delete_by_tenant_id", "success").Inc()
	return deletedCount, nil
}

// GetActiveSessionCount returns an approximate count of active sessions
func (m *SessionManager) GetActiveSessionCount(ctx context.Context) (int64, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("count").Observe(time.Since(startTime).Seconds())
	}()

	pattern := m.formattedKey("*")
	count, err := m.client.Keys(ctx, pattern).Result()
	if err != nil {
		m.logger.Error("Failed to count active sessions",
			ErrorField(err),
		)
		sessionOperations.WithLabelValues("count", "error").Inc()
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}

	m.logger.Debug("Active session count",
		Int("count", len(count)),
	)

	// Update the Prometheus gauge with the actual count
	activeSessions.Set(float64(len(count)))

	sessionOperations.WithLabelValues("count", "success").Inc()
	return int64(len(count)), nil
}

// CleanExpiredSessions deletes all expired sessions
func (m *SessionManager) CleanExpiredSessions(ctx context.Context) (int, error) {
	startTime := time.Now()
	defer func() {
		sessionOperationDuration.WithLabelValues("clean_expired").Observe(time.Since(startTime).Seconds())
	}()

	// In Redis, expired keys are automatically removed eventually, but we might
	// want to actively clean them to help with metrics accuracy
	pattern := m.formattedKey("*")
	var deletedCount int
	var cursor uint64 = 0
	now := time.Now().UTC()

	for {
		var keys []string
		var err error
		keys, cursor, err = m.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			m.logger.Error("Failed to scan keys for expired sessions",
				ErrorField(err),
			)
			sessionOperations.WithLabelValues("clean_expired", "error").Inc()
			return deletedCount, fmt.Errorf("failed to scan keys: %w", err)
		}

		// Check each key we found
		if len(keys) > 0 {
			pipe := m.client.Pipeline()
			gets := make(map[string]*redis.StringCmd)

			for _, key := range keys {
				gets[key] = pipe.Get(ctx, key)
			}

			// Execute gets
			_, err = pipe.Exec(ctx)
			if err != nil && err != redis.Nil {
				m.logger.Error("Failed to get session data during expired session cleanup",
					ErrorField(err),
				)
				// Continue with any keys we can read
			}

			// Check each session for expiration
			toDelete := make([]string, 0)
			for key, cmd := range gets {
				data, err := cmd.Bytes()
				if err != nil {
					if err == redis.Nil {
						// Already expired and cleaned by Redis
						continue
					}
					// Invalid but we should clean it
					toDelete = append(toDelete, key)
					continue
				}

				var session Session
				if err := json.Unmarshal(data, &session); err != nil {
					// Corrupted, we should clean it
					toDelete = append(toDelete, key)
					continue
				}

				// Check expiration
				if now.After(session.ExpiresAt) {
					toDelete = append(toDelete, key)
				}
			}

			// Delete expired sessions
			if len(toDelete) > 0 {
				if err := m.client.Del(ctx, toDelete...).Err(); err != nil {
					m.logger.Error("Failed to delete expired sessions",
						Int("found_count", len(toDelete)),
						ErrorField(err),
					)
					sessionOperations.WithLabelValues("clean_expired", "error").Inc()
				} else {
					deletedCount += len(toDelete)
					activeSessions.Sub(float64(len(toDelete)))
				}
			}
		}

		// Exit loop when we've scanned all keys
		if cursor == 0 {
			break
		}
	}

	m.logger.Info("Expired sessions cleaned",
		Int("deleted_count", deletedCount),
	)

	sessionOperations.WithLabelValues("clean_expired", "success").Inc()
	return deletedCount, nil
}
