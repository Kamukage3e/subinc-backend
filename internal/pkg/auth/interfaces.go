package auth

import (
	"context"
	"time"
)

// AuthProvider defines the core interface for all authentication providers
type AuthProvider interface {
	// Name returns the unique identifier for this auth provider
	Name() string

	// Version returns the version string of this provider
	Version() string

	// Authenticate validates credentials and returns user information
	Authenticate(ctx context.Context, credentials map[string]interface{}) (*AuthResult, error)

	// VerifyToken validates a token and returns user information
	VerifyToken(ctx context.Context, token string) (*AuthResult, error)

	// RevokeToken invalidates an existing token
	RevokeToken(ctx context.Context, token string) error

	// RefreshToken creates a new token for a valid expired token
	RefreshToken(ctx context.Context, token string) (*TokenInfo, error)

	// GetCapabilities returns the features supported by this provider
	GetCapabilities() []Capability
}

// TokenInfo contains token metadata
type TokenInfo struct {
	// Token is the actual token string
	Token string `json:"token"`

	// RefreshToken is used to obtain a new token when this one expires
	RefreshToken string `json:"refresh_token,omitempty"`

	// ExpiresAt is when the token becomes invalid
	ExpiresAt time.Time `json:"expires_at"`

	// TokenType is the type of token (e.g., "bearer", "jwt", "session")
	TokenType string `json:"token_type"`
}

// AuthResult contains authentication result data
type AuthResult struct {
	// UserID is the unique identifier for the authenticated user
	UserID string `json:"user_id"`

	// TenantID is the tenant the user belongs to
	TenantID string `json:"tenant_id"`

	// Email is the user's email address
	Email string `json:"email,omitempty"`

	// Roles contains the user's roles
	Roles []string `json:"roles,omitempty"`

	// Token contains the authentication token information
	Token *TokenInfo `json:"token,omitempty"`

	// Claims contains additional provider-specific claims/attributes
	Claims map[string]interface{} `json:"claims,omitempty"`
}

// Capability represents a feature supported by an auth provider
type Capability string

// Standard capabilities
const (
	CapabilityPassword     Capability = "password"     // Standard username/password
	CapabilityOAuth        Capability = "oauth"        // OAuth/OIDC
	CapabilityMFA          Capability = "mfa"          // Multi-factor auth
	CapabilitySAML         Capability = "saml"         // SAML
	CapabilityAPIKey       Capability = "api_key"      // API key auth
	CapabilityStateless    Capability = "stateless"    // Stateless tokens (e.g. JWT)
	CapabilityStateful     Capability = "stateful"     // Stateful sessions
	CapabilitySSO          Capability = "sso"          // Single sign-on
	CapabilityRegistration Capability = "registration" // Self-registration
	CapabilityPasswordless Capability = "passwordless" // Passwordless authentication
)
