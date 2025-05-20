package commonutil

import (
	"strings"

	"github.com/gofiber/fiber/v2"
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
	// Try to get user ID from context/headers
	if c != nil {
		// Check for X-User-ID header
		if userID := c.Get("X-User-ID"); userID != "" {
			return userID
		}

		// Check for Authorization header (JWT often contains user info)
		if auth := c.Get("Authorization"); auth != "" && strings.HasPrefix(auth, "Bearer ") {
			return "user_from_token" // In a real implementation, would parse the token
		}

		// Check locals (fiber's context store)
		if userID, ok := c.Locals("user_id").(string); ok && userID != "" {
			return userID
		}
	}

	return "system"
}
