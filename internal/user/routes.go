package user

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/middleware"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

type Deps struct {
	UserHandler    *UserHandler
	SecretsManager secrets.SecretsManager
	JWTSecretName  string
	BillingRepo    repository.BillingRepository
}

// RegisterRoutes registers all user-related routes under /users.
// All endpoints are production-grade, secure, and modular for SaaS.
func RegisterRoutes(router fiber.Router, deps Deps) {
	userGroup := router.Group("/users")
	userGroup.Post("/login",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.Login,
	)
	// MFA endpoints
	userGroup.Post("/mfa/enroll",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.EnrollMFA,
	)
	userGroup.Post("/mfa/enable",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.EnableMFA,
	)
	userGroup.Post("/mfa/disable",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.DisableMFA,
	)
	userGroup.Post("/mfa/verify",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.VerifyMFA,
	)
	userGroup.Get("/mfa/backup-codes",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.ListBackupCodes,
	)
	userGroup.Post("/mfa/backup-codes/regenerate",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.RegenerateBackupCodes,
	)
	userGroup.Post("/register", deps.UserHandler.Register)
	userGroup.Post("/forgot-password",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.ForgotPassword,
	)
	userGroup.Post("/reset-password",
		middleware.IPBlacklistMiddleware(),
		middleware.RateLimitMiddlewarePerDeviceIP(),
		deps.UserHandler.ResetPassword,
	)
	userGroup.Post("/verify-email", deps.UserHandler.VerifyEmail)
	userGroup.Post("/resend-verification", deps.UserHandler.ResendVerification)
	userGroup.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "service": "cost-management"})
	})
	// Authenticated user endpoints
	authUserGroup := userGroup.Group("", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: deps.SecretsManager,
		JWTSecretName:  deps.JWTSecretName,
	}))
	authUserGroup.Use(DeviceSessionMiddleware(deps.UserHandler.store))
	authUserGroup.Post("/logout", deps.UserHandler.Logout)
	authUserGroup.Post("/refresh", deps.UserHandler.Refresh)
	authUserGroup.Get("/", deps.UserHandler.ListUsers)
	authUserGroup.Get(":id", deps.UserHandler.GetUserByID)
	authUserGroup.Put(":id", deps.UserHandler.UpdateUser)
	authUserGroup.Delete(":id", deps.UserHandler.DeleteUser)
	authUserGroup.Post(":id/roles", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.AssignRole)
	authUserGroup.Delete(":id/roles/:role", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.RemoveRole)
	authUserGroup.Post(":id/attributes", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.SetAttribute)
	authUserGroup.Delete(":id/attributes/:key", middleware.RBACMiddleware("admin", "owner"), deps.UserHandler.RemoveAttribute)
	authUserGroup.Get("/profile", deps.UserHandler.GetProfile)
}
