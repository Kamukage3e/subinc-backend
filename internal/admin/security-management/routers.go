package security_management

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// Architectural decision: All security-management endpoints use in-memory rate limiting and strict security headers.
// Sensitive endpoints have stricter limits.
func RegisterAdminSecurityRoutes(router fiber.Router, handler *SecurityHandler, jwtSecretName string) {
	sec := router.Group("/security-management", securityHeadersMiddleware())

	// General rate limiter: 30 req/min/IP
	generalLimiter := newInMemoryRateLimiter(30, time.Minute)
	// Sensitive: 10 req/min/IP
	strictLimiter := newInMemoryRateLimiter(10, time.Minute)

	sec.Post("/users/security-events", generalLimiter.middleware(), handler.ListUserSecurityEvents)
	sec.Post("/users/login-history", generalLimiter.middleware(), handler.ListUserLoginHistory)
	sec.Post("/users/mfa/enable", strictLimiter.middleware(), handler.EnableMFA)
	sec.Post("/users/mfa/disable", strictLimiter.middleware(), handler.DisableMFA)
	sec.Post("/users/password/reset", strictLimiter.middleware(), handler.ResetUserPassword)
	sec.Post("/users/sessions/list", generalLimiter.middleware(), handler.ListUserSessions)
	sec.Post("/users/sessions/revoke", generalLimiter.middleware(), handler.RevokeUserSession)
	sec.Post("/audit-logs/list", generalLimiter.middleware(), handler.ListSecurityAuditLogs)
	sec.Post("/users/api-keys/list", generalLimiter.middleware(), handler.ListUserAPIKeys)
	sec.Post("/users/api-keys/create", strictLimiter.middleware(), handler.CreateUserAPIKey)
	sec.Post("/users/api-keys/revoke", strictLimiter.middleware(), handler.RevokeUserAPIKey)
	sec.Post("/users/devices/list", generalLimiter.middleware(), handler.ListUserDevices)
	sec.Post("/users/devices/revoke", generalLimiter.middleware(), handler.RevokeUserDevice)
	sec.Post("/breaches/list", generalLimiter.middleware(), handler.ListBreaches)
	sec.Post("/policies/list", generalLimiter.middleware(), handler.ListSecurityPolicies)
	sec.Post("/policies/create", generalLimiter.middleware(), handler.CreateSecurityPolicy)
	sec.Post("/policies/update", generalLimiter.middleware(), handler.UpdateSecurityPolicy)
	sec.Post("/policies/delete", generalLimiter.middleware(), handler.DeleteSecurityPolicy)
	sec.Post("/webhooks/create", generalLimiter.middleware(), handler.CreateWebhook)
	sec.Post("/webhooks/list", generalLimiter.middleware(), handler.ListWebhooks)
	sec.Post("/webhooks/delete", strictLimiter.middleware(), handler.DeleteWebhook)
	sec.Post("/webhooks/trigger", strictLimiter.middleware(), handler.TriggerWebhook)
	sec.Post("/password-reset/request", strictLimiter.middleware(), handler.RequestPasswordResetToken)
	sec.Post("/password-reset/verify", strictLimiter.middleware(), handler.VerifyPasswordResetToken)
	sec.Post("/password-reset/use", strictLimiter.middleware(), handler.UsePasswordResetToken)
	sec.Post("/rate-limit/set", strictLimiter.middleware(), handler.SetRateLimit)
	sec.Get("/rate-limit/get", strictLimiter.middleware(), handler.GetRateLimit)
	sec.Post("/rate-limit/delete", strictLimiter.middleware(), handler.DeleteRateLimit)
}
