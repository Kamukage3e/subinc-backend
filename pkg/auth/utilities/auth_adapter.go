package utilities

// This package provides utility functions and adapters to help with
// authentication without creating import cycles

import (
	"context"

	"github.com/subinc/subinc-backend/internal/pkg/auth"
)

// SecurityUser represents the minimal user information needed for authentication
type SecurityUser struct {
	ID     string   `json:"id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles,omitempty"`
	Status string   `json:"status,omitempty"`
}

// CreateLoginResult creates a standardized login result format
func CreateLoginResult(accessToken, refreshToken, tokenType string, expiresAt interface{}) map[string]interface{} {
	return map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_at":    expiresAt,
		"token_type":    tokenType,
	}
}

// Session represents the minimal session information needed
type Session struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Data      map[string]interface{} `json:"data"`
	ExpiresAt interface{}            `json:"expires_at"`
}

// AuthenticateWithProvider is a helper function to authenticate a user with a provider
func AuthenticateWithProvider(
	ctx context.Context,
	authManager *auth.AuthManager,
	providerName string,
	user SecurityUser,
	tenantID string,
	sessionData map[string]interface{},
) (*auth.AuthResult, error) {
	// Try to get the specified provider
	provider, err := authManager.GetProvider(providerName)
	if err != nil {
		// Try the default provider
		provider, err = authManager.GetDefaultProvider()
		if err != nil {
			return nil, err
		}
	}

	// Prepare credentials
	credentials := map[string]interface{}{
		"user_id":   user.ID,
		"email":     user.Email,
		"tenant_id": tenantID,
	}

	// Add roles if available
	if len(user.Roles) > 0 {
		credentials["roles"] = user.Roles
	}

	// Add session data
	for k, v := range sessionData {
		credentials[k] = v
	}

	// Authenticate with the provider
	return provider.Authenticate(ctx, credentials)
}
