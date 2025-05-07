package middleware

import (
	"net/http"
	"strings"

	"log"

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
			logAccessAttempt("unknown", allowedRoles, c.Method(), c.Path(), false, "no user context")
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no user context"})
		}
		user := "unknown"
		if u, ok := claims["sub"].(string); ok {
			user = u
		}
		rolesIface, ok := claims["roles"]
		if !ok {
			logAccessAttempt(user, allowedRoles, c.Method(), c.Path(), false, "no roles claim")
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
				logAccessAttempt(user, allowedRoles, c.Method(), c.Path(), true, "role allowed")
				return c.Next()
			}
		}
		logAccessAttempt(user, allowedRoles, c.Method(), c.Path(), false, "insufficient role")
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient role"})
	}
}

// logAccessAttempt logs RBAC access attempts for auditing
func logAccessAttempt(user string, allowedRoles []string, method, path string, allowed bool, reason string) {
	// Replace with production logger or audit log as needed
	log.Printf("RBAC access: user=%s allowedRoles=%v method=%s path=%s allowed=%v reason=%s", user, allowedRoles, method, path, allowed, reason)
}
