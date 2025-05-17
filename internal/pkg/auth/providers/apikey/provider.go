package apikey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/auth"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// APIKeyStore defines the interface for storing and retrieving API keys
type APIKeyStore interface {
	// VerifyAPIKey validates an API key and returns user information
	VerifyAPIKey(ctx context.Context, apiKey string) (APIKeyInfo, error)

	// RevokeAPIKey invalidates an API key
	RevokeAPIKey(ctx context.Context, apiKey string) error

	// CreateAPIKey generates a new API key for the specified user
	CreateAPIKey(ctx context.Context, userID, tenantID, name, scope string, expiresAt *time.Time) (APIKeyInfo, error)
}

// APIKeyInfo contains information about an API key
type APIKeyInfo struct {
	// ID is the unique identifier for this API key
	ID string

	// UserID is the user who owns this API key
	UserID string

	// TenantID is the tenant this API key belongs to
	TenantID string

	// Key is the actual API key value (only available on creation)
	Key string

	// Name is a human-readable identifier for this key
	Name string

	// Scope defines what this API key can access
	Scope string

	// CreatedAt is when this API key was created
	CreatedAt time.Time

	// UpdatedAt is when this API key was last updated
	UpdatedAt time.Time

	// ExpiresAt is when this API key expires
	ExpiresAt *time.Time

	// RevokedAt is when this API key was revoked, if it was
	RevokedAt *time.Time

	// LastUsedAt is when this API key was last used
	LastUsedAt *time.Time

	// Roles contains the user's roles inherited from the user
	Roles []string
}

// Config holds configuration for the API key provider
type Config struct {
	// Store is the API key store implementation
	Store APIKeyStore

	// Logger for logging errors and debugging info
	Logger *logger.Logger

	// HeaderName is the HTTP header to look for API keys in
	HeaderName string

	// QueryParam is the query parameter to look for API keys in
	QueryParam string
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		Store:      nil, // Must be provided
		Logger:     logger.Default,
		HeaderName: "X-API-Key",
		QueryParam: "api_key",
	}
}

// APIKeyProvider implements the AuthProvider interface for API keys
type APIKeyProvider struct {
	config Config
	logger *logger.Logger
}

// NewAPIKeyProvider creates a new API key provider
func NewAPIKeyProvider(config Config) (*APIKeyProvider, error) {
	if config.Store == nil {
		return nil, errors.New("apikey: store cannot be nil")
	}

	if config.Logger == nil {
		config.Logger = logger.Default
	}

	return &APIKeyProvider{
		config: config,
		logger: config.Logger,
	}, nil
}

// Name returns the provider name
func (p *APIKeyProvider) Name() string {
	return "apikey"
}

// Version returns the provider version
func (p *APIKeyProvider) Version() string {
	return "1.0.0"
}

// GetCapabilities returns this provider's capabilities
func (p *APIKeyProvider) GetCapabilities() []auth.Capability {
	return []auth.Capability{
		auth.CapabilityAPIKey,
		auth.CapabilityStateful,
	}
}

// Authenticate validates credentials and returns user information
// For API keys, this just delegates to VerifyToken
func (p *APIKeyProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.AuthResult, error) {
	apiKey, ok := credentials["api_key"].(string)
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("apikey: %w: api_key required", auth.ErrInvalidCredentials)
	}

	return p.VerifyToken(ctx, apiKey)
}

// VerifyToken validates an API key and returns user information
func (p *APIKeyProvider) VerifyToken(ctx context.Context, token string) (*auth.AuthResult, error) {
	keyInfo, err := p.config.Store.VerifyAPIKey(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("apikey: %w", auth.ErrInvalidToken)
	}

	// Check if API key is expired
	if keyInfo.ExpiresAt != nil && time.Now().After(*keyInfo.ExpiresAt) {
		return nil, fmt.Errorf("apikey: %w: key expired", auth.ErrInvalidToken)
	}

	// Check if API key is revoked
	if keyInfo.RevokedAt != nil {
		return nil, fmt.Errorf("apikey: %w: key revoked", auth.ErrTokenRevoked)
	}

	// Create auth result
	result := &auth.AuthResult{
		UserID:   keyInfo.UserID,
		TenantID: keyInfo.TenantID,
		Roles:    keyInfo.Roles,
		Token: &auth.TokenInfo{
			Token:     token,
			TokenType: "apikey",
		},
		Claims: map[string]interface{}{
			"provider":   p.Name(),
			"key_id":     keyInfo.ID,
			"key_name":   keyInfo.Name,
			"key_scope":  keyInfo.Scope,
			"created_at": keyInfo.CreatedAt,
		},
	}

	// Add optional fields
	if keyInfo.ExpiresAt != nil {
		result.Token.ExpiresAt = *keyInfo.ExpiresAt
		result.Claims["expires_at"] = *keyInfo.ExpiresAt
	}

	if keyInfo.LastUsedAt != nil {
		result.Claims["last_used_at"] = *keyInfo.LastUsedAt
	}

	return result, nil
}

// RevokeToken invalidates an API key
func (p *APIKeyProvider) RevokeToken(ctx context.Context, token string) error {
	return p.config.Store.RevokeAPIKey(ctx, token)
}

// RefreshToken is not supported for API keys
func (p *APIKeyProvider) RefreshToken(ctx context.Context, token string) (*auth.TokenInfo, error) {
	return nil, auth.ErrUnsupportedOperation
}

// CreateAPIKey generates a new API key for a user
func (p *APIKeyProvider) CreateAPIKey(ctx context.Context, userID, tenantID, name, scope string, expiresAt *time.Time) (APIKeyInfo, error) {
	return p.config.Store.CreateAPIKey(ctx, userID, tenantID, name, scope, expiresAt)
}
