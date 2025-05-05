package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/spf13/viper"
)

// ConfigureCORS creates a CORS middleware with secure defaults
func ConfigureCORS() fiber.Handler {
	// Read allowed origins from config if available
	allowedOrigins := viper.GetString("cors.origins")
	if allowedOrigins == "" {
		// Default to secure settings (no wildcard)
		allowedOrigins = "https://app.subinc.com,https://admin.subinc.com"
	}

	// Read allowed methods from config if available
	allowedMethods := viper.GetString("cors.methods")
	if allowedMethods == "" {
		// Default to safe methods and common "write" methods
		allowedMethods = "GET,POST,PUT,DELETE,OPTIONS"
	}

	// Read allowed headers from config if available
	allowedHeaders := viper.GetString("cors.headers")
	if allowedHeaders == "" {
		// Default to essential headers only
		allowedHeaders = "Origin,Content-Type,Accept,Authorization,X-Requested-With"
	}

	// Create secure CORS configuration
	return cors.New(cors.Config{
		// Only allow specified origins
		AllowOrigins: allowedOrigins,

		// Only allow specified methods
		AllowMethods: allowedMethods,

		// Only allow specified headers
		AllowHeaders: allowedHeaders,

		// Block cookies and credentials by default
		// Change to true only if cross-domain auth with cookies is required
		AllowCredentials: viper.GetBool("cors.allow_credentials"),

		// Expose safe headers
		ExposeHeaders: "X-Total-Count,X-Request-ID",

		// Cache preflight requests for better performance
		MaxAge: 86400, // 24 hours
	})
}
