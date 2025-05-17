package rbacmiddleware

import (
	"github.com/gofiber/fiber/v2"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	"github.com/subinc/subinc-backend/internal/pkg/auth"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// RBACMiddleware enforces RBAC/ABAC for a given resource/action.
func RBACMiddleware(resource, action string, abacContext map[string]interface{}) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID, ok := c.Locals("user_id").(string)
		if !ok || userID == "" {
			return auth.ToFiberError(auth.NewAuthError(
				auth.ErrorTypeAuthorization,
				"User ID missing from request context",
				"RBAC_AUTH_001",
				nil,
			))
		}

		allowed, err := rbac_management.GlobalRBACStore().CheckAccess(c.Context(), userID, resource, action, abacContext)
		if err != nil {
			logger.Default.Error("RBAC check failed",
				logger.String("user_id", userID),
				logger.String("resource", resource),
				logger.String("action", action),
				logger.ErrorField(err),
			)

			return auth.ToFiberError(auth.NewAuthError(
				auth.ErrorTypeInternal,
				"RBAC check failed",
				"RBAC_ERROR_001",
				err,
			))
		}

		if !allowed {
			logger.Default.Info("RBAC access denied",
				logger.String("user_id", userID),
				logger.String("resource", resource),
				logger.String("action", action),
			)

			return auth.ToFiberError(auth.NewAuthError(
				auth.ErrorTypeAuthorization,
				"Insufficient permissions",
				"RBAC_DENIED_001",
				nil,
			))
		}

		return c.Next()
	}
}
