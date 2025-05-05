package middleware

import (
	"net/http"
	"strings"

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
		rolesIface, ok := claims["roles"]
		if !ok {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no roles claim"})
		}
		var userRoles []string
		switch v := rolesIface.(type) {
		case []interface{}:
			for _, r := range v {
				if s, ok := r.(string); ok {
					userRoles = append(userRoles, s)
				}
			}
		case []string:
			userRoles = v
		case string:
			userRoles = strings.Split(v, ",")
		}
		for _, r := range userRoles {
			if _, allowed := roleSet[r]; allowed {
				return c.Next()
			}
		}
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient role"})
	}
}
