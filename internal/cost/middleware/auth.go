package middleware

import (
	"net/http"
	"strings"

	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

type AuthMiddlewareConfig struct {
	SecretsManager secrets.SecretsManager
	JWTSecretName  string
}

func AuthMiddleware(cfg AuthMiddlewareConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid authorization header"})
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		jwtSecret, err := cfg.SecretsManager.GetSecret(context.Background(), cfg.JWTSecretName)
		if err != nil || jwtSecret == "" {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "server misconfiguration"})
		}
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(http.StatusUnauthorized, "unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired token"})
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token claims"})
		}
		c.Locals("claims", claims)
		return c.Next()
	}
}

func UserFromContext(c *fiber.Ctx) map[string]interface{} {
	claims, ok := c.Locals("claims").(jwt.MapClaims)
	if !ok {
		return nil
	}
	return claims
}
