package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Middleware options
type MiddlewareConfig struct {
	// AuthManager is the central auth manager
	AuthManager *AuthManager

	// PreferredProvider is the preferred auth provider name
	// If empty, will try all providers or use the default
	PreferredProvider string

	// PreferredProviders is an ordered list of preferred provider names
	// If set, these providers will be tried in order before falling back to the default
	PreferredProviders []string

	// AllowMultipleProviders determines if multiple providers should be attempted
	// If true, will try providers in order defined by PreferredProviders
	AllowMultipleProviders bool

	// RequiredCapabilities specifies capabilities that must be supported by the provider
	RequiredCapabilities []Capability

	// TokenLookup specifies where to find the auth token
	// Format: "header:<n>,cookie:<n>,query:<n>,param:<n>"
	// Default: "header:Authorization"
	TokenLookup string

	// ProviderTokenLookup specifies token lookup configuration for specific providers
	// Map of provider name to token lookup string
	ProviderTokenLookup map[string]string

	// TokenHandler is a custom function to extract the token
	TokenHandler func(*fiber.Ctx) (string, error)

	// CustomTokenExtractors provides provider-specific token extraction logic
	// Map of provider name to token extraction function
	CustomTokenExtractors map[string]func(*fiber.Ctx) (string, error)

	// ContextKey is the key used to store auth result in context
	ContextKey string

	// Logger is the logger instance to use
	Logger *logger.Logger

	// SuccessHandler is called when authentication succeeds
	SuccessHandler func(*fiber.Ctx, *AuthResult) error

	// ErrorHandler is called when authentication fails
	ErrorHandler func(*fiber.Ctx, error) error

	// SkipRoutes contains paths to skip auth for (prefix matching)
	SkipRoutes []string

	// ContinueOnError determines if the request should proceed on auth error
	// Useful for making auth optional while still populating context when successful
	ContinueOnError bool
}

// DefaultConfig returns a default middleware configuration
func DefaultMiddlewareConfig(authManager *AuthManager) MiddlewareConfig {
	return MiddlewareConfig{
		AuthManager:            authManager,
		TokenLookup:            "header:Authorization",
		ContextKey:             "auth",
		Logger:                 logger.Default,
		ContinueOnError:        false,
		ErrorHandler:           defaultErrorHandler,
		SuccessHandler:         defaultSuccessHandler,
		AllowMultipleProviders: true,
		PreferredProviders:     []string{},
		ProviderTokenLookup:    map[string]string{},
		CustomTokenExtractors:  map[string]func(*fiber.Ctx) (string, error){},
	}
}

// Helper functions for token extraction
func extractTokenFromHeader(c *fiber.Ctx, header string) (string, error) {
	auth := c.Get(header)
	if auth == "" {
		return "", NewAuthError(
			ErrorTypeValidation,
			fmt.Sprintf("Missing authentication header: %s", header),
			"AUTH_HEADER_001",
			nil,
		)
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return "", NewAuthError(
			ErrorTypeValidation,
			"Invalid authentication header format - expected 'Bearer <token>'",
			"AUTH_HEADER_002",
			nil,
		)
	}

	return strings.TrimPrefix(auth, "Bearer "), nil
}

func extractTokenFromCookie(c *fiber.Ctx, cookie string) (string, error) {
	token := c.Cookies(cookie)
	if token == "" {
		return "", NewAuthError(
			ErrorTypeValidation,
			fmt.Sprintf("Missing authentication cookie: %s", cookie),
			"AUTH_COOKIE_001",
			nil,
		)
	}
	return token, nil
}

func extractTokenFromQuery(c *fiber.Ctx, param string) (string, error) {
	token := c.Query(param)
	if token == "" {
		return "", NewAuthError(
			ErrorTypeValidation,
			fmt.Sprintf("Missing authentication query parameter: %s", param),
			"AUTH_QUERY_001",
			nil,
		)
	}
	return token, nil
}

func defaultErrorHandler(c *fiber.Ctx, err error) error {
	// Default response is 401 Unauthorized
	status := fiber.StatusUnauthorized
	errorResponse := fiber.Map{
		"error": "Authentication failed",
		"code":  "AUTH_ERROR",
	}

	// Add request info to the logger context
	reqID := c.GetRespHeader("X-Request-ID")
	userID, _ := c.Locals("user_id").(string)
	path := c.Path()

	// Check if it's our custom AuthError
	var authError *AuthError
	if errors.As(err, &authError) {
		switch authError.Type {
		case ErrorTypeConfiguration:
			// Server misconfiguration should not be exposed to user
			status = fiber.StatusInternalServerError
			errorResponse["error"] = "Authentication service misconfigured"
			errorResponse["code"] = authError.Code

			// Log the actual error for admins
			logger.Default.Error("Auth configuration error",
				logger.String("code", authError.Code),
				logger.String("message", authError.Message),
				logger.String("request_id", reqID),
				logger.String("path", path),
				logger.String("user_id", userID),
				logger.ErrorField(authError.Original),
			)

		case ErrorTypeAuthentication:
			status = fiber.StatusUnauthorized
			errorResponse["error"] = "Invalid authentication"
			errorResponse["code"] = authError.Code

		case ErrorTypeAuthorization:
			// Authorization failures are 403 Forbidden
			status = fiber.StatusForbidden
			errorResponse["error"] = "Access denied"
			errorResponse["code"] = authError.Code

		case ErrorTypeValidation:
			// Validation errors are 400 Bad Request
			status = fiber.StatusBadRequest
			errorResponse["error"] = authError.Message
			errorResponse["code"] = authError.Code

		case ErrorTypeToken:
			// Use a generic message for token errors to avoid leaking info
			status = fiber.StatusUnauthorized
			errorResponse["error"] = "Invalid or expired token"
			errorResponse["code"] = authError.Code

		case ErrorTypeProvider:
			// Internal provider errors should be 500s
			status = fiber.StatusInternalServerError
			errorResponse["error"] = "Authentication provider error"
			errorResponse["code"] = authError.Code

			// Log the actual error for admins
			logger.Default.Error("Auth provider error",
				logger.String("code", authError.Code),
				logger.String("message", authError.Message),
				logger.String("request_id", reqID),
				logger.String("path", path),
				logger.String("user_id", userID),
				logger.ErrorField(authError.Original),
			)

		case ErrorTypeInternal:
			// Internal errors are 500s
			status = fiber.StatusInternalServerError
			errorResponse["error"] = "Authentication service error"
			errorResponse["code"] = authError.Code

			// Log the actual error for admins
			logger.Default.Error("Auth internal error",
				logger.String("code", authError.Code),
				logger.String("message", authError.Message),
				logger.String("request_id", reqID),
				logger.String("path", path),
				logger.String("user_id", userID),
				logger.ErrorField(authError.Original),
			)

		default:
			// Unknown error types default to 401
			status = fiber.StatusUnauthorized
			errorResponse["error"] = "Authentication failed"
			errorResponse["code"] = authError.Code
		}
	} else {
		// For generic errors, provide minimal information
		errorResponse["error"] = "Authentication failed"

		// Log the unexpected error
		logger.Default.Error("Unexpected auth error",
			logger.ErrorField(err),
		)
	}

	return c.Status(status).JSON(errorResponse)
}

func defaultSuccessHandler(c *fiber.Ctx, result *AuthResult) error {
	// Store user info in context for handlers to use
	c.Locals("user_id", result.UserID)
	if result.TenantID != "" {
		c.Locals("tenant_id", result.TenantID)
	}
	if result.Email != "" {
		c.Locals("email", result.Email)
	}
	if len(result.Roles) > 0 {
		c.Locals("roles", result.Roles)
	}

	// Store the full auth result
	c.Locals("auth_result", result)

	return c.Next()
}

// Middleware returns a Fiber middleware for authentication
func Middleware(config MiddlewareConfig) fiber.Handler {
	// Validate configuration
	if config.AuthManager == nil {
		panic("auth middleware: AuthManager is required")
	}

	if config.Logger == nil {
		config.Logger = logger.Default
	}

	if config.ContextKey == "" {
		config.ContextKey = "auth"
	}

	if config.SuccessHandler == nil {
		config.SuccessHandler = defaultSuccessHandler
	}

	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}

	// Create default token extractor function based on TokenLookup
	defaultExtractor := buildTokenExtractor(config.TokenLookup, config.TokenHandler)

	// Build provider-specific token extractors
	providerExtractors := make(map[string]func(*fiber.Ctx) (string, error))

	// Add custom extractors from config
	for provider, extractor := range config.CustomTokenExtractors {
		providerExtractors[provider] = extractor
	}

	// Build extractors from ProviderTokenLookup
	for provider, lookup := range config.ProviderTokenLookup {
		if _, exists := providerExtractors[provider]; !exists {
			providerExtractors[provider] = buildTokenExtractor(lookup, nil)
		}
	}

	// Return the actual middleware handler
	return func(c *fiber.Ctx) error {
		// Skip authentication for certain routes
		path := c.Path()
		for _, skipPath := range config.SkipRoutes {
			if strings.HasPrefix(path, skipPath) {
				return c.Next()
			}
		}

		// Create a context with timeout
		ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
		defer cancel()

		// Determine which providers to try and in what order
		var providersToTry []string

		// If we have explicitly preferred providers, use those first
		if len(config.PreferredProviders) > 0 {
			for _, provider := range config.PreferredProviders {
				// Only include if it matches required capabilities
				if len(config.RequiredCapabilities) > 0 {
					hasAllCaps, err := hasAllCapabilities(ctx, config.AuthManager, provider, config.RequiredCapabilities)
					if err != nil {
						config.Logger.Warn("Error checking provider capabilities",
							logger.String("provider", provider),
							logger.ErrorField(err),
						)
						continue
					}
					if !hasAllCaps {
						continue
					}
				}
				providersToTry = append(providersToTry, provider)
			}
		}

		// Add the single preferred provider if set and not already in the list
		if config.PreferredProvider != "" && !contains(providersToTry, config.PreferredProvider) {
			// Only include if it matches required capabilities
			if len(config.RequiredCapabilities) > 0 {
				hasAllCaps, err := hasAllCapabilities(ctx, config.AuthManager, config.PreferredProvider, config.RequiredCapabilities)
				if err == nil && hasAllCaps {
					providersToTry = append(providersToTry, config.PreferredProvider)
				}
			} else {
				providersToTry = append(providersToTry, config.PreferredProvider)
			}
		}

		// If no explicit providers and we have capabilities, find matching providers
		if len(providersToTry) == 0 && len(config.RequiredCapabilities) > 0 {
			for _, capability := range config.RequiredCapabilities {
				providers := config.AuthManager.GetProvidersByCapability(capability)
				for _, provider := range providers {
					if !contains(providersToTry, provider.Name()) {
						providersToTry = append(providersToTry, provider.Name())
					}
				}
			}
		}

		// Try all providers if allowed and we don't already have a specific list
		tryAllProviders := config.AllowMultipleProviders && len(providersToTry) == 0

		var lastErr error
		var authResult *AuthResult

		// If we have specific providers to try
		if len(providersToTry) > 0 {
			// Try each provider in order
			for _, providerName := range providersToTry {
				// Get the provider-specific token extractor if available
				extractor, ok := providerExtractors[providerName]
				if !ok {
					extractor = defaultExtractor
				}

				// Extract the token
				token, err := extractor(c)
				if err != nil {
					lastErr = fmt.Errorf("provider %s: %w", providerName, err)
					continue
				}

				// Verify the token with this provider
				result, err := config.AuthManager.VerifyToken(ctx, token, providerName)
				if err == nil {
					authResult = result
					break
				}

				lastErr = fmt.Errorf("provider %s: %w", providerName, err)
			}
		} else if tryAllProviders {
			// Extract the token with the default extractor
			token, err := defaultExtractor(c)
			if err != nil {
				if config.ContinueOnError {
					return c.Next()
				}
				return config.ErrorHandler(c, err)
			}

			// Try all providers to verify the token
			authResult, lastErr = config.AuthManager.VerifyToken(ctx, token, "")
		} else {
			// Extract the token with the default extractor
			token, err := defaultExtractor(c)
			if err != nil {
				if config.ContinueOnError {
					return c.Next()
				}
				return config.ErrorHandler(c, err)
			}

			// Use the default provider
			provider, err := config.AuthManager.GetDefaultProvider()
			if err != nil {
				return config.ErrorHandler(c, fmt.Errorf("default provider not available: %w", err))
			}

			authResult, lastErr = provider.VerifyToken(ctx, token)
		}

		// If we couldn't authenticate with any provider
		if authResult == nil {
			if config.ContinueOnError {
				return c.Next()
			}
			if lastErr != nil {
				return config.ErrorHandler(c, lastErr)
			}
			return config.ErrorHandler(c, errors.New("authentication failed with all providers"))
		}

		// Store the auth result in the context for handlers to use
		c.Locals(config.ContextKey, authResult)

		// Apply authentication result to the request
		return config.SuccessHandler(c, authResult)
	}
}

// Helper function to check if a provider has all required capabilities
func hasAllCapabilities(ctx context.Context, authManager *AuthManager, providerName string, requiredCapabilities []Capability) (bool, error) {
	provider, err := authManager.GetProvider(providerName)
	if err != nil {
		return false, err
	}

	providerCaps := provider.GetCapabilities()
	for _, reqCap := range requiredCapabilities {
		found := false
		for _, cap := range providerCaps {
			if cap == reqCap {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	return true, nil
}

// buildTokenExtractor creates a token extraction function based on TokenLookup configuration
func buildTokenExtractor(tokenLookup string, tokenHandler func(*fiber.Ctx) (string, error)) func(*fiber.Ctx) (string, error) {
	if tokenHandler != nil {
		return tokenHandler
	}

	// Default to Authorization header if not specified
	lookup := tokenLookup
	if lookup == "" {
		lookup = "header:Authorization"
	}

	// Parse token lookup configuration
	parts := strings.Split(lookup, ",")
	extractFuncs := make([]func(*fiber.Ctx) (string, error), 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			panic("auth middleware: invalid TokenLookup format, should be <source>:<n>")
		}

		source := strings.TrimSpace(kv[0])
		name := strings.TrimSpace(kv[1])

		switch source {
		case "header":
			extractFuncs = append(extractFuncs, func(c *fiber.Ctx) (string, error) {
				return extractTokenFromHeader(c, name)
			})
		case "cookie":
			extractFuncs = append(extractFuncs, func(c *fiber.Ctx) (string, error) {
				return extractTokenFromCookie(c, name)
			})
		case "query":
			extractFuncs = append(extractFuncs, func(c *fiber.Ctx) (string, error) {
				return extractTokenFromQuery(c, name)
			})
		default:
			panic("auth middleware: invalid TokenLookup source, should be 'header', 'cookie', or 'query'")
		}
	}

	// Create the combined extractor function that tries each method in order
	return func(c *fiber.Ctx) (string, error) {
		var token string
		var lastErr error

		for _, extract := range extractFuncs {
			token, lastErr = extract(c)
			if lastErr == nil {
				return token, nil
			}
		}

		if lastErr != nil {
			return "", lastErr
		}

		return "", errors.New("no authentication token found")
	}
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
