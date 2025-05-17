package passwordless

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/auth"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// TokenStore defines the interface for storing and retrieving magic tokens
type TokenStore interface {
	// StoreToken stores a token for a user
	StoreToken(ctx context.Context, userID, email, token string, expiresAt time.Time) error

	// VerifyToken validates a token and returns the associated user and token data
	VerifyToken(ctx context.Context, token string) (TokenInfo, error)

	// InvalidateToken marks a token as used
	InvalidateToken(ctx context.Context, token string) error

	// CleanupExpiredTokens removes expired tokens
	CleanupExpiredTokens(ctx context.Context) error
}

// UserStore defines the interface for retrieving user information
type UserStore interface {
	// GetUserByEmail looks up a user by email address
	GetUserByEmail(ctx context.Context, email string) (UserInfo, error)

	// GetUserRoles retrieves roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

// DeliveryService defines the interface for delivering magic links/tokens
type DeliveryService interface {
	// SendMagicLink sends a magic link to the user
	SendMagicLink(ctx context.Context, email, token, redirectURL string) error
}

// TokenInfo contains information about a magic token
type TokenInfo struct {
	// ID is the unique identifier for this token
	ID string

	// UserID is the user who this token is for
	UserID string

	// Email is the email address this token was sent to
	Email string

	// Token is the actual token value
	Token string

	// CreatedAt is when this token was created
	CreatedAt time.Time

	// ExpiresAt is when this token expires
	ExpiresAt time.Time

	// UsedAt is when this token was used, if it was
	UsedAt *time.Time
}

// UserInfo contains basic user information
type UserInfo struct {
	// ID is the unique identifier for the user
	ID string

	// Email is the user's email address
	Email string

	// TenantID is the tenant the user belongs to
	TenantID string
}

// Config holds configuration for the passwordless provider
type Config struct {
	// TokenStore is the token store implementation
	TokenStore TokenStore

	// UserStore is the user store implementation
	UserStore UserStore

	// DeliveryService is the service for delivering magic links
	DeliveryService DeliveryService

	// Logger for logging errors and debugging info
	Logger *logger.Logger

	// TokenExpiry is how long magic tokens are valid for
	TokenExpiry time.Duration

	// RedirectURL is the base URL to redirect to after token verification
	RedirectBaseURL string

	// TokenLength is the length of generated tokens in bytes
	TokenLength int

	// SessionExpiry is how long sessions created with magic links are valid
	SessionExpiry time.Duration
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		TokenStore:      nil, // Must be provided
		UserStore:       nil, // Must be provided
		DeliveryService: nil, // Must be provided
		Logger:          logger.Default,
		TokenExpiry:     15 * time.Minute,
		RedirectBaseURL: "https://app.example.com/auth/verify",
		TokenLength:     32,
		SessionExpiry:   24 * time.Hour,
	}
}

// PasswordlessProvider implements the AuthProvider interface for passwordless authentication
type PasswordlessProvider struct {
	config Config
	logger *logger.Logger
}

// NewPasswordlessProvider creates a new passwordless auth provider
func NewPasswordlessProvider(config Config) (*PasswordlessProvider, error) {
	if config.TokenStore == nil {
		return nil, errors.New("passwordless: token store cannot be nil")
	}

	if config.UserStore == nil {
		return nil, errors.New("passwordless: user store cannot be nil")
	}

	if config.DeliveryService == nil {
		return nil, errors.New("passwordless: delivery service cannot be nil")
	}

	if config.Logger == nil {
		config.Logger = logger.Default
	}

	if config.TokenExpiry <= 0 {
		config.TokenExpiry = 15 * time.Minute
	}

	if config.TokenLength <= 0 {
		config.TokenLength = 32
	}

	if config.SessionExpiry <= 0 {
		config.SessionExpiry = 24 * time.Hour
	}

	return &PasswordlessProvider{
		config: config,
		logger: config.Logger,
	}, nil
}

// Name returns the provider name
func (p *PasswordlessProvider) Name() string {
	return "passwordless"
}

// Version returns the provider version
func (p *PasswordlessProvider) Version() string {
	return "1.0.0"
}

// GetCapabilities returns this provider's capabilities
func (p *PasswordlessProvider) GetCapabilities() []auth.Capability {
	return []auth.Capability{
		auth.CapabilityStateful,
		auth.CapabilityPasswordless,
	}
}

// generateToken creates a secure random token
func (p *PasswordlessProvider) generateToken() (string, error) {
	b := make([]byte, p.config.TokenLength)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// RequestMagicLink starts the passwordless auth flow by sending a magic link
func (p *PasswordlessProvider) RequestMagicLink(ctx context.Context, email string) error {
	// Look up the user by email
	user, err := p.config.UserStore.GetUserByEmail(ctx, email)
	if err != nil {
		p.logger.Warn("Passwordless login requested for non-existent email",
			logger.String("email", email),
			logger.ErrorField(err),
		)
		// Don't reveal if the email exists or not
		return nil
	}

	// Generate a secure token
	token, err := p.generateToken()
	if err != nil {
		p.logger.Error("Failed to generate token",
			logger.String("email", email),
			logger.ErrorField(err),
		)
		return fmt.Errorf("passwordless: failed to generate token: %w", err)
	}

	// Calculate expiry time
	expiresAt := time.Now().Add(p.config.TokenExpiry)

	// Store the token
	err = p.config.TokenStore.StoreToken(ctx, user.ID, email, token, expiresAt)
	if err != nil {
		p.logger.Error("Failed to store token",
			logger.String("email", email),
			logger.ErrorField(err),
		)
		return fmt.Errorf("passwordless: failed to store token: %w", err)
	}

	// Send the magic link
	err = p.config.DeliveryService.SendMagicLink(ctx, email, token, p.config.RedirectBaseURL)
	if err != nil {
		p.logger.Error("Failed to send magic link",
			logger.String("email", email),
			logger.ErrorField(err),
		)
		return fmt.Errorf("passwordless: failed to send magic link: %w", err)
	}

	return nil
}

// Authenticate validates credentials and returns user information
func (p *PasswordlessProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.AuthResult, error) {
	// For passwordless, we expect either an email to start the flow or a token to complete it

	// Check if this is a token verification request
	if token, ok := credentials["token"].(string); ok && token != "" {
		return p.VerifyToken(ctx, token)
	}

	// Otherwise, check if this is a magic link request
	if email, ok := credentials["email"].(string); ok && email != "" {
		if err := p.RequestMagicLink(ctx, email); err != nil {
			return nil, fmt.Errorf("passwordless: failed to send magic link: %w", err)
		}
		return nil, fmt.Errorf("passwordless: %w: magic link sent", auth.ErrUnsupportedOperation)
	}

	return nil, fmt.Errorf("passwordless: %w: email or token required", auth.ErrInvalidCredentials)
}

// VerifyToken validates a magic token and returns user information
func (p *PasswordlessProvider) VerifyToken(ctx context.Context, token string) (*auth.AuthResult, error) {
	// Verify the token
	tokenInfo, err := p.config.TokenStore.VerifyToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("passwordless: %w", auth.ErrInvalidToken)
	}

	// Check if token is expired
	if time.Now().After(tokenInfo.ExpiresAt) {
		return nil, fmt.Errorf("passwordless: %w: token expired", auth.ErrInvalidToken)
	}

	// Check if token has already been used
	if tokenInfo.UsedAt != nil {
		return nil, fmt.Errorf("passwordless: %w: token already used", auth.ErrInvalidToken)
	}

	// Get user roles
	roles, err := p.config.UserStore.GetUserRoles(ctx, tokenInfo.UserID)
	if err != nil {
		roles = []string{} // Default to empty roles if there's an error
	}

	// Mark the token as used (but continue even if this fails)
	_ = p.config.TokenStore.InvalidateToken(ctx, token)

	// Create auth result
	result := &auth.AuthResult{
		UserID: tokenInfo.UserID,
		Email:  tokenInfo.Email,
		Roles:  roles,
		Token: &auth.TokenInfo{
			Token:     token, // Note: typically we'd generate a session token here
			TokenType: "passwordless",
			ExpiresAt: time.Now().Add(p.config.SessionExpiry),
		},
		Claims: map[string]interface{}{
			"provider":   p.Name(),
			"created_at": tokenInfo.CreatedAt,
		},
	}

	return result, nil
}

// RevokeToken invalidates a magic token
func (p *PasswordlessProvider) RevokeToken(ctx context.Context, token string) error {
	return p.config.TokenStore.InvalidateToken(ctx, token)
}

// RefreshToken is not supported for magic links
func (p *PasswordlessProvider) RefreshToken(ctx context.Context, token string) (*auth.TokenInfo, error) {
	return nil, auth.ErrUnsupportedOperation
}
