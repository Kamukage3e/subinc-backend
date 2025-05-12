package contextutil

import "github.com/gofiber/fiber/v2"

// getActorID extracts the actor/user ID from Fiber context headers. Used for audit, RBAC, etc.
func GetActorID(c *fiber.Ctx) string {
	id := c.Get("X-Actor-ID")
	if id != "" {
		return id
	}
	id = c.Get("X-User-ID")
	if id != "" {
		return id
	}
	return ""
}
