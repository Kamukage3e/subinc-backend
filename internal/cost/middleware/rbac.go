package middleware

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// RBACMiddleware returns a Fiber middleware that enforces role-based access control
func RBACMiddleware(allowedRoles ...string) fiber.Handler {
	roleSet := make(map[string]struct{}, len(allowedRoles))
	for _, r := range allowedRoles {
		roleSet[r] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		claims := UserFromContext(c)
		if claims == nil {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no user context"})
		}
		roleVal, ok := claims["role"]
		if !ok {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no role claim"})
		}
		role, ok := roleVal.(string)
		if !ok {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: invalid role claim"})
		}
		if _, allowed := roleSet[role]; !allowed {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient role"})
		}
		return c.Next()
	}
}
