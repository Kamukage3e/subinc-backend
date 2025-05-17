package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/auth"
	"github.com/subinc/subinc-backend/internal/pkg/interfaces"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Config holds configuration for the session provider
type Config struct {
	// SessionService is the session service implementation to use
	SessionService interfaces.SessionService

	// CookieName is the name of the cookie where the session ID is stored
	CookieName string

	// SessionTTL is how long sessions are valid for
	SessionTTL time.Duration

	// Logger for logging
	Logger *logger.Logger

	// AllowedRolesKey is the key in session data where roles are stored
	AllowedRolesKey string
}

// DefaultConfig returns a default session configuration
func DefaultConfig() Config {
	return Config{
		SessionService:  nil, // Must be provided
		CookieName:      "session_id",
		SessionTTL:      24 * time.Hour,
		AllowedRolesKey: "roles",
	}
}

// SessionProvider implements the AuthProvider interface for sessions
type SessionProvider struct {
	config Config
	logger *logger.Logger
}

// NewSessionProvider creates a new session auth provider
func NewSessionProvider(config Config) (*SessionProvider, error) {
	if config.SessionService == nil {
		return nil, errors.New("session: session service cannot be nil")
	}

	if config.CookieName == "" {
		config.CookieName = "session_id"
	}

	if config.SessionTTL <= 0 {
		config.SessionTTL = 24 * time.Hour
	}

	if config.Logger == nil {
		config.Logger = logger.Default
	}

	return &SessionProvider{
		config: config,
		logger: config.Logger,
	}, nil
}

// Name returns the provider name
func (p *SessionProvider) Name() string {
	return "session"
}

// Version returns the provider version
func (p *SessionProvider) Version() string {
	return "1.0.0"
}

// GetCapabilities returns this provider's capabilities
func (p *SessionProvider) GetCapabilities() []auth.Capability {
	return []auth.Capability{
		auth.CapabilityStateful,
	}
}

// Authenticate creates a new session for the user
func (p *SessionProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.AuthResult, error) {
	// Session provider expects credentials to contain userID and other session data
	userID, ok := credentials["user_id"].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("session: %w: user_id required", auth.ErrInvalidCredentials)
	}

	tenantID, _ := credentials["tenant_id"].(string)
	email, _ := credentials["email"].(string)

	// Extract roles if provided
	var roles []string
	if rolesClaim, ok := credentials["roles"]; ok {
		if rolesList, ok := rolesClaim.([]string); ok {
			roles = rolesList
		} else if rolesIfcList, ok := rolesClaim.([]interface{}); ok {
			roles = make([]string, 0, len(rolesIfcList))
			for _, r := range rolesIfcList {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
		}
	}

	// Prepare session data
	sessionData := make(map[string]interface{})
	if email != "" {
		sessionData["email"] = email
	}

	if len(roles) > 0 {
		sessionData[p.config.AllowedRolesKey] = roles
	}

	// Copy additional data from credentials
	for key, value := range credentials {
		switch key {
		case "user_id", "tenant_id", "email", "roles":
			// Skip standard fields that are already handled
			continue
		default:
			sessionData[key] = value
		}
	}

	// Create a new session
	sess, err := p.config.SessionService.CreateSession(ctx, userID, tenantID, sessionData)
	if err != nil {
		return nil, fmt.Errorf("session: failed to create session: %w", err)
	}

	// Create token info
	tokenInfo := &auth.TokenInfo{
		Token:     sess.ID,
		TokenType: "session",
		ExpiresAt: sess.ExpiresAt,
	}

	// Create auth result
	result := &auth.AuthResult{
		UserID:   userID,
		TenantID: tenantID,
		Email:    email,
		Roles:    roles,
		Token:    tokenInfo,
		Claims: map[string]interface{}{
			"provider":      p.Name(),
			"created_at":    sess.CreatedAt,
			"last_accessed": sess.LastAccessAt,
		},
	}

	return result, nil
}

// VerifyToken validates a session token and returns user information
func (p *SessionProvider) VerifyToken(ctx context.Context, token string) (*auth.AuthResult, error) {
	// Get the session from the session service
	sess, err := p.config.SessionService.GetSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session: failed to get session: %w", auth.ErrInvalidToken)
	}

	// Create token info
	tokenInfo := &auth.TokenInfo{
		Token:     sess.ID,
		TokenType: "session",
		ExpiresAt: sess.ExpiresAt,
	}

	// Extract roles from session data
	var roles []string
	if rolesData, ok := sess.Data[p.config.AllowedRolesKey]; ok {
		if rolesList, ok := rolesData.([]string); ok {
			roles = rolesList
		} else if rolesIfcList, ok := rolesData.([]interface{}); ok {
			roles = make([]string, 0, len(rolesIfcList))
			for _, r := range rolesIfcList {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
		}
	}

	// Get email from session data
	email, _ := sess.Data["email"].(string)

	// Create auth result
	result := &auth.AuthResult{
		UserID:   sess.UserID,
		TenantID: sess.TenantID,
		Email:    email,
		Roles:    roles,
		Token:    tokenInfo,
		Claims: map[string]interface{}{
			"provider":      p.Name(),
			"created_at":    sess.CreatedAt,
			"last_accessed": sess.LastAccessAt,
		},
	}

	// Copy additional data from the session
	for key, value := range sess.Data {
		switch key {
		case "email", p.config.AllowedRolesKey:
			// Skip standard fields that are already handled
			continue
		default:
			result.Claims[key] = value
		}
	}

	return result, nil
}

// RevokeToken invalidates a session
func (p *SessionProvider) RevokeToken(ctx context.Context, token string) error {
	return p.config.SessionService.DeleteSession(ctx, token)
}

// RefreshToken extends a session's lifetime
func (p *SessionProvider) RefreshToken(ctx context.Context, token string) (*auth.TokenInfo, error) {
	// Extended session expiry
	sess, err := p.config.SessionService.RefreshSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session: failed to refresh session: %w", auth.ErrInvalidToken)
	}

	return &auth.TokenInfo{
		Token:     sess.ID,
		TokenType: "session",
		ExpiresAt: sess.ExpiresAt,
	}, nil
}

// CreateSession is a convenience method to create a new session
func (p *SessionProvider) CreateSession(ctx context.Context, userID, tenantID, email string, roles []string, data map[string]interface{}) (*auth.AuthResult, error) {
	credentials := map[string]interface{}{
		"user_id":   userID,
		"tenant_id": tenantID,
		"email":     email,
		"roles":     roles,
	}

	// Copy additional data
	for k, v := range data {
		credentials[k] = v
	}

	return p.Authenticate(ctx, credentials)
}

// GetSession retrieves a session by ID
func (p *SessionProvider) GetSession(ctx context.Context, sessionID string) (*auth.AuthResult, error) {
	return p.VerifyToken(ctx, sessionID)
}

// DeleteSession removes a session
func (p *SessionProvider) DeleteSession(ctx context.Context, sessionID string) error {
	return p.RevokeToken(ctx, sessionID)
}

// RotateSession creates a new session and invalidates the old one
func (p *SessionProvider) RotateSession(ctx context.Context, sessionID string) (*auth.AuthResult, error) {
	// Get the current session
	oldSession, err := p.config.SessionService.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session: failed to get session for rotation: %w", err)
	}

	// Create a new session with the same data
	credentials := map[string]interface{}{
		"user_id":   oldSession.UserID,
		"tenant_id": oldSession.TenantID,
	}

	// Copy all data from the old session
	for k, v := range oldSession.Data {
		credentials[k] = v
	}

	// Authenticate to create a new session
	result, err := p.Authenticate(ctx, credentials)
	if err != nil {
		return nil, fmt.Errorf("session: failed to create new session during rotation: %w", err)
	}

	// Delete the old session
	err = p.config.SessionService.DeleteSession(ctx, sessionID)
	if err != nil {
		p.logger.Warn("Failed to delete old session during rotation",
			logger.String("old_session_id", sessionID),
			logger.String("new_session_id", result.Token.Token),
			logger.ErrorField(err),
		)
		// Continue even if delete fails, as we have a new session
	}

	return result, nil
}
