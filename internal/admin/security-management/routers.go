package security_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminSecurityRoutes(router fiber.Router, handler *SecurityAdminHandler) {
	sec := router.Group("/security-management")

	sec.Get("/users/:id/security-events", handler.ListUserSecurityEvents)
	sec.Get("/users/:id/login-history", handler.ListUserLoginHistory)
	sec.Post("/users/:id/mfa/enable", handler.EnableMFA)
	sec.Post("/users/:id/mfa/disable", handler.DisableMFA)
	sec.Post("/users/:id/password/reset", handler.ResetUserPassword)
	sec.Get("/users/:id/sessions", handler.ListUserSessions)
	sec.Delete("/users/:id/sessions/:session_id", handler.RevokeUserSession)
	sec.Get("/audit-logs", handler.ListSecurityAuditLogs)
	sec.Get("/users/get/:id/api-keys", handler.ListUserAPIKeys)
	sec.Post("/users/create/:id/api-keys", handler.CreateUserAPIKey)
	sec.Delete("/users/delete/:id/api-keys/:key_id", handler.RevokeUserAPIKey)
	sec.Get("/users/get/:id/devices", handler.ListUserDevices)
	sec.Delete("/users/revoke/:id/devices/:device_id", handler.RevokeUserDevice)
	sec.Get("/breaches/list", handler.ListBreaches)
	sec.Get("/policies/list", handler.ListSecurityPolicies)
	sec.Post("/policies/create", handler.CreateSecurityPolicy)
	sec.Put("/policies/update/:id", handler.UpdateSecurityPolicy)
	sec.Delete("/policies/delete/:id", handler.DeleteSecurityPolicy)
}
