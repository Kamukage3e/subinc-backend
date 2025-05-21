package auth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// AuthError represents a standardized authentication error
type AuthError struct {
	// Type categorizes the error
	Type ErrorType
	// Message provides human-readable description
	Message string
	// Code is a unique error code for clients and logging
	Code string
	// Original contains the wrapped original error
	Original error
}

// Error satisfies the error interface
func (e *AuthError) Error() string {
	if e.Original != nil {
		return fmt.Sprintf("%s: %s (code: %s) - %v", e.Type, e.Message, e.Code, e.Original)
	}
	return fmt.Sprintf("%s: %s (code: %s)", e.Type, e.Message, e.Code)
}

// Unwrap allows errors.Is and errors.As to work with wrapped errors
func (e *AuthError) Unwrap() error {
	return e.Original
}

// ErrorType represents auth error categories
type ErrorType string

// Error type constants
const (
	ErrorTypeConfiguration  ErrorType = "configuration_error"  // Config-related errors
	ErrorTypeAuthentication ErrorType = "authentication_error" // Auth failure errors
	ErrorTypeAuthorization  ErrorType = "authorization_error"  // Permission errors
	ErrorTypeValidation     ErrorType = "validation_error"     // Input validation errors
	ErrorTypeProvider       ErrorType = "provider_error"       // Provider-specific errors
	ErrorTypeInternal       ErrorType = "internal_error"       // Internal system errors
	ErrorTypeToken          ErrorType = "token_error"          // Token-specific errors
	ErrorTypeSession        ErrorType = "session_error"        // Session-specific errors
	ErrorTypeMFA            ErrorType = "mfa_error"            // MFA-related errors
	ErrorTypeNetworking     ErrorType = "networking_error"     // Network communication errors
	ErrorTypeStorage        ErrorType = "storage_error"        // Database/storage errors
	ErrorTypeBreach         ErrorType = "security_breach"      // Security violation errors
)

// NewAuthError creates a new standardized auth error
func NewAuthError(errType ErrorType, message, code string, original error) *AuthError {
	return &AuthError{
		Type:     errType,
		Message:  message,
		Code:     code,
		Original: original,
	}
}

// PublicMessage returns a user-safe error message
func (e *AuthError) PublicMessage() string {
	// Return user-safe messages that don't expose implementation details
	switch e.Type {
	case ErrorTypeConfiguration, ErrorTypeInternal, ErrorTypeStorage, ErrorTypeNetworking:
		return "An internal system error occurred. Please contact support."
	case ErrorTypeAuthentication:
		return "Authentication failed. Please check your credentials."
	case ErrorTypeAuthorization:
		return "You don't have permission to perform this action."
	case ErrorTypeToken:
		return "Your authentication token is invalid or expired. Please log in again."
	case ErrorTypeSession:
		return "Your session has expired. Please log in again."
	case ErrorTypeMFA:
		return "Multi-factor authentication failed. Please try again."
	case ErrorTypeBreach:
		return "A security violation was detected. Please contact support."
	default:
		return e.Message // For validation errors, we can show the actual message
	}
}

// StatusCode returns the appropriate HTTP status code for this error
func (e *AuthError) StatusCode() int {
	switch e.Type {
	case ErrorTypeConfiguration, ErrorTypeInternal, ErrorTypeStorage:
		return 500 // Internal Server Error
	case ErrorTypeNetworking:
		return 503 // Service Unavailable
	case ErrorTypeAuthentication, ErrorTypeToken, ErrorTypeSession:
		return 401 // Unauthorized
	case ErrorTypeAuthorization:
		return 403 // Forbidden
	case ErrorTypeValidation:
		return 400 // Bad Request
	case ErrorTypeMFA:
		return 401 // Unauthorized (could be 400 in some cases)
	case ErrorTypeBreach:
		return 403 // Forbidden
	case ErrorTypeProvider:
		return 500 // Internal Server Error
	default:
		return 400 // Default to Bad Request
	}
}

// LogFields returns structured log fields for this error
func (e *AuthError) LogFields() []logger.Field {
	fields := []logger.Field{
		logger.String("error_type", string(e.Type)),
		logger.String("error_code", e.Code),
		logger.String("error_message", e.Message),
	}

	if e.Original != nil {
		fields = append(fields, logger.ErrorField(e.Original))
	}

	return fields
}

// Pre-defined auth errors
var (
	// Provider errors
	ErrProviderNotFound = NewAuthError(
		ErrorTypeProvider,
		"Authentication provider not found",
		"AUTH_PROVIDER_001",
		nil,
	)

	ErrProviderAlreadyExist = NewAuthError(
		ErrorTypeProvider,
		"Authentication provider already registered",
		"AUTH_PROVIDER_002",
		nil,
	)

	ErrInvalidProvider = NewAuthError(
		ErrorTypeProvider,
		"Invalid provider type",
		"AUTH_PROVIDER_003",
		nil,
	)

	// Authentication errors
	ErrInvalidCredentials = NewAuthError(
		ErrorTypeAuthentication,
		"Invalid credentials provided",
		"AUTH_CREDS_001",
		nil,
	)

	ErrUserNotFound = NewAuthError(
		ErrorTypeAuthentication,
		"User not found",
		"AUTH_CREDS_002",
		nil,
	)

	ErrUserDisabled = NewAuthError(
		ErrorTypeAuthentication,
		"User account is disabled",
		"AUTH_CREDS_003",
		nil,
	)

	ErrUserLocked = NewAuthError(
		ErrorTypeAuthentication,
		"User account is locked",
		"AUTH_CREDS_004",
		nil,
	)

	// Token errors
	ErrInvalidToken = NewAuthError(
		ErrorTypeToken,
		"Invalid or expired token",
		"AUTH_TOKEN_001",
		nil,
	)

	ErrTokenRevoked = NewAuthError(
		ErrorTypeToken,
		"Token has been revoked",
		"AUTH_TOKEN_002",
		nil,
	)

	ErrTokenExpired = NewAuthError(
		ErrorTypeToken,
		"Token has expired",
		"AUTH_TOKEN_003",
		nil,
	)

	// Validation errors
	ErrMissingParameter = NewAuthError(
		ErrorTypeValidation,
		"Required parameter missing",
		"AUTH_PARAM_001",
		nil,
	)

	ErrInvalidParameter = NewAuthError(
		ErrorTypeValidation,
		"Invalid parameter",
		"AUTH_PARAM_002",
		nil,
	)

	// Session errors
	ErrSessionNotFound = NewAuthError(
		ErrorTypeSession,
		"Session not found or expired",
		"AUTH_SESSION_001",
		nil,
	)

	ErrSessionRevoked = NewAuthError(
		ErrorTypeSession,
		"Session has been revoked",
		"AUTH_SESSION_002",
		nil,
	)

	// Capability errors
	ErrUnsupportedOperation = NewAuthError(
		ErrorTypeProvider,
		"Operation not supported by provider",
		"AUTH_CAPABILITY_001",
		nil,
	)

	// MFA errors
	ErrMFARequired = NewAuthError(
		ErrorTypeMFA,
		"Multi-factor authentication required",
		"AUTH_MFA_001",
		nil,
	)

	ErrMFAFailed = NewAuthError(
		ErrorTypeMFA,
		"Multi-factor authentication verification failed",
		"AUTH_MFA_002",
		nil,
	)
)

// DefaultProviderName is the name of the default auth provider
const DefaultProviderName = "default"

// AuthManager is the central registry and manager for auth providers
type AuthManager struct {
	defaultProvider string
	providers       map[string]AuthProvider
	logger          *logger.Logger
	mu              sync.RWMutex
}

// NewAuthManager creates a new auth manager with optional initial providers
func NewAuthManager(loggerInstance *logger.Logger) *AuthManager {
	if loggerInstance == nil {
		// Use the default logger if none provided
		loggerInstance = logger.Default
	}

	return &AuthManager{
		providers:       make(map[string]AuthProvider),
		defaultProvider: DefaultProviderName,
		logger:          loggerInstance,
	}
}

// RegisterProvider adds a new auth provider to the registry
func (m *AuthManager) RegisterProvider(provider AuthProvider) error {
	if provider == nil {
		return NewAuthError(
			ErrorTypeValidation,
			"Provider cannot be nil",
			"AUTH_PARAM_003",
			nil,
		)
	}

	name := provider.Name()
	if name == "" {
		return NewAuthError(
			ErrorTypeValidation,
			"Provider name cannot be empty",
			"AUTH_PARAM_004",
			nil,
		)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; exists {
		return NewAuthError(
			ErrorTypeProvider,
			fmt.Sprintf("Provider already registered: %s", name),
			"AUTH_PROVIDER_002",
			nil,
		)
	}

	m.providers[name] = provider
	m.logger.Info("Registered auth provider",
		logger.String("provider_name", name),
		logger.String("provider_version", provider.Version()),
	)

	return nil
}

// UnregisterProvider removes a provider from the registry
func (m *AuthManager) UnregisterProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; !exists {
		return NewAuthError(
			ErrorTypeProvider,
			fmt.Sprintf("Provider not found: %s", name),
			"AUTH_PROVIDER_001",
			nil,
		)
	}

	delete(m.providers, name)
	m.logger.Info("Unregistered auth provider", logger.String("provider_name", name))

	return nil
}

// GetProvider retrieves a provider by name
func (m *AuthManager) GetProvider(name string) (AuthProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, exists := m.providers[name]
	if !exists {
		return nil, NewAuthError(
			ErrorTypeProvider,
			fmt.Sprintf("Provider not found: %s", name),
			"AUTH_PROVIDER_001",
			nil,
		)
	}

	return provider, nil
}

// GetProviderAs retrieves a provider by name and casts it to the specified type
// This allows accessing provider-specific functionality beyond the basic interface
func (m *AuthManager) GetProviderAs(name string, providerType interface{}) error {
	provider, err := m.GetProvider(name)
	if err != nil {
		return err
	}

	// Use reflection to set the provider to the desired type
	val := reflect.ValueOf(providerType).Elem()
	if !val.CanSet() {
		return NewAuthError(
			ErrorTypeValidation,
			"Provider type cannot be set",
			"AUTH_PROVIDER_004",
			nil,
		)
	}

	// Check if the provider is of the requested type
	providerVal := reflect.ValueOf(provider)
	if !providerVal.Type().AssignableTo(val.Type()) {
		expectedType := val.Type().String()
		actualType := providerVal.Type().String()

		return NewAuthError(
			ErrorTypeProvider,
			fmt.Sprintf("Provider type mismatch: expected %s but got %s", expectedType, actualType),
			"AUTH_PROVIDER_003",
			nil,
		)
	}

	// Set the value
	val.Set(providerVal)
	return nil
}

// GetDefaultProvider returns the default auth provider
func (m *AuthManager) GetDefaultProvider() (AuthProvider, error) {
	return m.GetProvider(m.defaultProvider)
}

// SetDefaultProvider changes the default provider
func (m *AuthManager) SetDefaultProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; !exists {
		return NewAuthError(
			ErrorTypeProvider,
			fmt.Sprintf("Provider not found: %s", name),
			"AUTH_PROVIDER_001",
			nil,
		)
	}

	m.defaultProvider = name
	m.logger.Info("Changed default auth provider", logger.String("provider_name", name))

	return nil
}

// ListProviders returns a list of all registered provider names
func (m *AuthManager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]string, 0, len(m.providers))
	for name := range m.providers {
		providers = append(providers, name)
	}

	return providers
}

// GetProvidersByCapability returns providers that support a specific capability
func (m *AuthManager) GetProvidersByCapability(capability Capability) []AuthProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matching []AuthProvider
	for _, provider := range m.providers {
		for _, cap := range provider.GetCapabilities() {
			if cap == capability {
				matching = append(matching, provider)
				break
			}
		}
	}

	return matching
}

// Authenticate delegates authentication to the specified provider
func (m *AuthManager) Authenticate(ctx context.Context, providerName string, credentials map[string]interface{}) (*AuthResult, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.Authenticate(ctx, credentials)
}

// VerifyToken validates a token with the appropriate provider
// If providerName is empty, tries all providers
func (m *AuthManager) VerifyToken(ctx context.Context, token string, providerName string) (*AuthResult, error) {
	// If token is empty, return validation error
	if token == "" {
		return nil, NewAuthError(
			ErrorTypeValidation,
			"Token cannot be empty",
			"AUTH_TOKEN_003",
			nil,
		)
	}

	// If provider specified, use only that provider
	if providerName != "" {
		provider, err := m.GetProvider(providerName)
		if err != nil {
			return nil, err
		}
		return provider.VerifyToken(ctx, token)
	}

	// Otherwise try all providers until one succeeds
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	for name, provider := range m.providers {
		result, err := provider.VerifyToken(ctx, token)
		if err == nil {
			// Add the provider name to the auth result if not already present
			if result.Claims == nil {
				result.Claims = map[string]interface{}{}
			}
			if _, ok := result.Claims["provider"]; !ok {
				result.Claims["provider"] = name
			}
			return result, nil
		}

		// Wrap provider-specific errors
		lastErr = NewAuthError(
			ErrorTypeToken,
			fmt.Sprintf("Provider %s failed to verify token", name),
			"AUTH_TOKEN_004",
			err,
		)
	}

	if lastErr != nil {
		return nil, NewAuthError(
			ErrorTypeToken,
			"No provider could verify token",
			"AUTH_TOKEN_005",
			lastErr,
		)
	}

	return nil, ErrInvalidToken
}

// RevokeToken invalidates a token with the specified provider
func (m *AuthManager) RevokeToken(ctx context.Context, token string, providerName string) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return err
	}

	return provider.RevokeToken(ctx, token)
}

// RefreshToken creates a new token using the specified provider
func (m *AuthManager) RefreshToken(ctx context.Context, token string, providerName string) (*TokenInfo, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.RefreshToken(ctx, token)
}

// HasCapability checks if a specific provider supports a capability
func (m *AuthManager) HasCapability(providerName string, capability Capability) (bool, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return false, err
	}

	capabilities := provider.GetCapabilities()
	for _, cap := range capabilities {
		if cap == capability {
			return true, nil
		}
	}

	return false, nil
}

// ToFiberError converts an AuthError to a Fiber-compatible error response
func ToFiberError(err error) error {
	if err == nil {
		return nil
	}

	// Default status and message if not an AuthError
	status := 500
	message := "Internal server error"

	// Convert to AuthError if possible
	var authError *AuthError
	if errors.As(err, &authError) {
		status = authError.StatusCode()
		message = authError.PublicMessage()

		// Log the detailed error
		logger.Default.Error("Auth error occurred",
			authError.LogFields()...,
		)
	} else {
		// Unknown error type, log it as internal error
		logger.Default.Error("Unknown auth error",
			logger.ErrorField(err),
		)
	}

	// Return a fiber-compatible error
	return fiber.NewError(status, message)
}

// ToFiberErrorWithDetails returns a function that sets status code and returns JSON with error details
func ToFiberErrorWithDetails(err error) func(*fiber.Ctx) error {
	if err == nil {
		return func(c *fiber.Ctx) error {
			return nil
		}
	}

	// Default status and message if not an AuthError
	status := 500
	message := "Internal server error"
	errorCode := "UNKNOWN_ERROR"

	// Convert to AuthError if possible
	var authError *AuthError
	if errors.As(err, &authError) {
		status = authError.StatusCode()
		message = authError.PublicMessage()
		errorCode = authError.Code

		// Log the detailed error
		logger.Default.Error("Auth error occurred",
			authError.LogFields()...,
		)
	} else {
		// Unknown error type, log it as internal error
		logger.Default.Error("Unknown auth error",
			logger.ErrorField(err),
		)
	}

	// Return a function for detailed error response
	return func(c *fiber.Ctx) error {
		return c.Status(status).JSON(fiber.Map{
			"error": message,
			"code":  errorCode,
		})
	}
}

// WrapError wraps a regular error with an AuthError type if it's not already one
func WrapError(err error, errType ErrorType, message, code string) error {
	if err == nil {
		return nil
	}

	var authError *AuthError
	if errors.As(err, &authError) {
		return err // Already an AuthError, return as is
	}

	return NewAuthError(errType, message, code, err)
}

// Providers returns the providers map for direct access
func (m *AuthManager) Providers() map[string]AuthProvider {
	return m.providers
}
