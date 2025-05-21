package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// APIMiddlewareConfig holds configuration for all API middleware
type APIMiddlewareConfig struct {
	// Secret for ID hashing
	IDHashingSecret string
	// Salt for ID hashing
	IDHashingSalt string
	// Logger instance
	Logger *logger.Logger
	// Skip paths for ID hashing
	SkipPaths []string
}

// GlobalAPIMiddleware registers all global middleware for the API
func GlobalAPIMiddleware(app *fiber.App, config APIMiddlewareConfig) {
	if config.Logger == nil {
		config.Logger = logger.Default
	}

	// Apply ID hashing middleware to all routes
	// This will securely hash all ID values in API responses to prevent enumeration attacks
	app.Use(IDHashingMiddleware(IDHashingConfig{
		Secret: config.IDHashingSecret,
		Salt:   config.IDHashingSalt,
		Prefix: "api",
		Logger: config.Logger,
		FieldsToObfuscate: []string{
			"id", "tenant_id", "organization_id", "user_id", "uuid", "_id",
			"subscription_id", "payment_id", "invoice_id", "customer_id",
		},
		PathsToSkip: append([]string{
			"/health", "/metrics", "/static", "/docs", "/swagger",
			"/authentication", "/internal", "/debug",
		}, config.SkipPaths...),
		ResponseHashingEnabled: true,
		RequestHashingEnabled:  true,
	}))

	// Other global middleware can be added here
}

// CreateIDHashingMiddleware creates an ID hashing middleware for specific route groups
func CreateIDHashingMiddleware(pathPrefix string, idHashingSecret, idHashingSalt string) fiber.Handler {
	// This middleware can be added to specific routes
	return IDHashingMiddleware(IDHashingConfig{
		Secret: idHashingSecret,
		Salt:   idHashingSalt,
		Prefix: pathPrefix,
		Logger: logger.Default,
		FieldsToObfuscate: []string{
			"id", "uuid", "_id", "tenant_id",
		},
		PathsToSkip: []string{
			pathPrefix + "/health",
			pathPrefix + "/metrics",
		},
	})
}
