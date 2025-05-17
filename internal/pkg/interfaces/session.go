package interfaces

import (
	"context"
	"time"
)

// Session represents user session data that can be shared across packages
type Session struct {
	// Core fields
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`

	// Client info
	IP     string `json:"ip,omitempty"`
	Device string `json:"device,omitempty"`

	// Timing information
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastAccessAt time.Time `json:"last_access_at"`

	// Session data
	Data map[string]interface{} `json:"data,omitempty"`
}

// SessionService defines the interface for session management operations
type SessionService interface {
	// Create and manage sessions
	CreateSession(ctx context.Context, userID, tenantID string, data map[string]interface{}) (Session, error)
	GetSession(ctx context.Context, sessionID string) (Session, error)
	UpdateSession(ctx context.Context, sessionID string, data map[string]interface{}) (Session, error)
	RefreshSession(ctx context.Context, sessionID string) (Session, error)
	DeleteSession(ctx context.Context, sessionID string) error

	// User session management
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	DeleteUserSessions(ctx context.Context, userID string) (int, error)

	// Tenant-level operations
	DeleteTenantSessions(ctx context.Context, tenantID string) (int, error)

	// Utility operations
	GetActiveSessionCount(ctx context.Context) (int64, error)
	CleanExpiredSessions(ctx context.Context) (int, error)
}
