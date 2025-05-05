package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/helmet"
)

// SecurityHeaders returns a middleware that sets secure HTTP headers
func SecurityHeaders() fiber.Handler {
	// Use default helmet configuration which sets secure headers
	// This includes XSS Protection, Content Type Nosniff, and XFrame Options
	return helmet.New()
}
