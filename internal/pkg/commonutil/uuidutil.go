package commonutil

import (
	"os"
	"strings"

	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// GenerateUUID returns a new RFC4122 UUID string
// Centralized implementation to be used across all modules
func GenerateUUID() string {
	return uuid.NewString()
}

// IsValidUUID checks if a string is a valid UUID
func IsValidUUID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// GetActorOrSystem extracts the actor ID from the request context or returns "system" if not available
// This is a simplified replacement for the audit logger's actor extraction
func GetActorOrSystem(c *fiber.Ctx) string {
	if c != nil {
		if userID := c.Get("X-User-ID"); userID != "" {
			return userID
		}
		if auth := c.Get("Authorization"); auth != "" && strings.HasPrefix(auth, "Bearer ") {
			secret := os.Getenv("JWT_SECRET")
			if secret == "" {
				return "system"
			}
			tokenString := strings.TrimPrefix(auth, "Bearer ")
			userID, err := UserFromToken(tokenString, secret)
			if err == nil && userID != "" {
				return userID
			}
			return "system"
		}
		if userID, ok := c.Locals("user_id").(string); ok && userID != "" {
			return userID
		}
	}
	return "system"
}

func UserFromToken(tokenString string, secret string) (string, error) {
	if tokenString == "" {
		return "", errors.New("token is empty")
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", errors.New("user id not found in token")
	}
	return userID, nil
}
