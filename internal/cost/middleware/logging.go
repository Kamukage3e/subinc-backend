package middleware

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
)

// LoggingMiddleware logs each request with method, path, status, latency, and user (if present)
func LoggingMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		latency := time.Since(start)
		user := "anonymous"
		if claims := UserFromContext(c); claims != nil {
			if u, ok := claims["sub"].(string); ok {
				user = u
			}
		}
		log.Printf("%s %s %d %s user=%s", c.Method(), c.Path(), c.Response().StatusCode(), latency, user)
		return err
	}
}
