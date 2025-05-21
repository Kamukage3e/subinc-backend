package security_management

import (
	"context"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// securityHeadersMiddleware sets strict security headers for all responses.
func securityHeadersMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		return c.Next()
	}
}

// SessionAuthMiddleware validates session tokens provided in the Authorization header
func SessionAuthMiddleware(sessionService interface {
	GetSession(ctx context.Context, sessionID string) (Session, error)
}) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid Authorization header"})
		}

		sessionID := strings.TrimPrefix(authHeader, "Bearer ")
		if sessionID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session token required"})
		}

		session, err := sessionService.GetSession(c.Context(), sessionID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid session"})
		}

		// Check if session has expired
		if time.Now().UTC().After(session.ExpiresAt) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session expired"})
		}

		// Set user information in context for handlers to use
		c.Locals("user_id", session.UserID)
		c.Locals("session_id", session.ID)

		return c.Next()
	}
}

// OIDCMiddleware validates JWT/OIDC tokens and sets claims in context.
func OIDCMiddleware(jwtSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid Authorization header"})
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid claims"})
		}
		// Set user_id and claims in context for downstream handlers
		if userID, ok := claims["user_id"].(string); ok && userID != "" {
			c.Locals("user_id", userID)
		}
		c.Locals("claims", claims)
		return c.Next()
	}
}
