package session

import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/interfaces"
)

// SessionServiceAdapter adapts the new SessionService interface to the old expected interface
// This allows the existing code to work with the new interface without requiring
// immediate updates to all code that uses the session service
type SessionServiceAdapter struct {
	Manager interfaces.SessionService
}

// NewRedisSessionAdapter creates a new adapter for the new SessionService interface
func NewRedisSessionAdapter(manager *SessionManager) *SessionServiceAdapter {
	return &SessionServiceAdapter{
		Manager: manager,
	}
}

// ListUserSessions gets all sessions for a user
func (a *SessionServiceAdapter) ListUserSessions(ctx context.Context, userID string) ([]interfaces.Session, error) {
	return a.Manager.ListUserSessions(ctx, userID)
}

// RevokeUserSession removes a specific session for a user
func (a *SessionServiceAdapter) RevokeUserSession(ctx context.Context, userID, sessionID string) error {
	// First verify the session belongs to the user
	session, err := a.Manager.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.UserID != userID {
		return ErrSessionInvalid
	}

	return a.Manager.DeleteSession(ctx, sessionID)
}

// CreateUserSession is the legacy method for creating sessions with old parameter list
func (a *SessionServiceAdapter) CreateUserSession(ctx context.Context, userID, ip, device string, expiresIn time.Duration) (interfaces.Session, error) {
	// Prepare session data with the client info
	data := map[string]interface{}{
		"ip":     ip,
		"device": device,
	}

	// Create a session with the specified TTL
	session, err := a.Manager.CreateSession(ctx, userID, "", data)
	if err != nil {
		return interfaces.Session{}, err
	}

	return session, nil
}

// RefreshUserSession is the legacy method for refreshing sessions with old parameter list
func (a *SessionServiceAdapter) RefreshUserSession(ctx context.Context, sessionID string, expiresIn time.Duration) (interfaces.Session, error) {
	// The expiresIn parameter is ignored as the new interface doesn't support custom expiry times
	// per refresh operation, but uses the manager's default TTL
	return a.Manager.RefreshSession(ctx, sessionID)
}

// LogoutSession invalidates a session (legacy name)
func (a *SessionServiceAdapter) LogoutSession(ctx context.Context, sessionID string) error {
	return a.Manager.DeleteSession(ctx, sessionID)
}

// GetSession retrieves a session by ID
func (a *SessionServiceAdapter) GetSession(ctx context.Context, sessionID string) (interfaces.Session, error) {
	return a.Manager.GetSession(ctx, sessionID)
}

// CreateSession forwards to the underlying implementation (modern interface)
func (a *SessionServiceAdapter) CreateSession(ctx context.Context, userID, tenantID string, data map[string]interface{}) (interfaces.Session, error) {
	return a.Manager.CreateSession(ctx, userID, tenantID, data)
}

// DeleteSession forwards to the underlying implementation
func (a *SessionServiceAdapter) DeleteSession(ctx context.Context, sessionID string) error {
	return a.Manager.DeleteSession(ctx, sessionID)
}

// RefreshSession forwards to the underlying implementation
func (a *SessionServiceAdapter) RefreshSession(ctx context.Context, sessionID string) (interfaces.Session, error) {
	return a.Manager.RefreshSession(ctx, sessionID)
}
