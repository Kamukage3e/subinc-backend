package rbacmiddleware

import (
	"github.com/gofiber/fiber/v2"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
)

// RBACMiddleware enforces RBAC/ABAC for a given resource/action.
func RBACMiddleware(resource, action string, abacContext map[string]interface{}) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID, ok := c.Locals("user_id").(string)
		if !ok || userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: user_id missing"})
		}
		allowed, err := rbac_management.GlobalRBACStore().CheckAccess(c.Context(), userID, resource, action, abacContext)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "RBAC check failed"})
		}
		if !allowed {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient permissions"})
		}
		return c.Next()
	}
}
 