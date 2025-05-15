package security_management

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// Architectural decision: All security-management endpoints use in-memory rate limiting and strict security headers.
// Sensitive endpoints have stricter limits.
func RegisteryRoutes(router fiber.Router, handler *SecurityHandler, jwtSecretName string, auditLogger AuditLogger) {
	// General rate limiter: 30 req/min/IP
	generalLimiter := newInMemoryRateLimiter(30, time.Minute)
	// Sensitive: 10 req/min/IP
	strictLimiter := newInMemoryRateLimiter(10, time.Minute)

	// --- Auth ---
	route := router.Group("/auth", securityHeadersMiddleware())
	route.Post("/login", strictLimiter.middleware(), handler.Login)
	route.Post("/logout", strictLimiter.middleware(), handler.Logout)
	route.Post("/register", generalLimiter.middleware(), handler.Register)
	route.Post("/verify-email", generalLimiter.middleware(), handler.VerifyEmail)
	route.Post("/resend-verification", generalLimiter.middleware(), handler.ResendVerification)
	route.Post("/change-password", strictLimiter.middleware(), handler.ChangePassword)
	route.Get("/google", strictLimiter.middleware(), handler.AuthGoogle)
	route.Get("/google/callback", strictLimiter.middleware(), handler.AuthGoogleCallback)
	route.Get("/saml", strictLimiter.middleware(), handler.AuthSAML)
	route.Get("/saml/callback", strictLimiter.middleware(), handler.AuthSAMLCallback)
	route.Post("/token/refresh", strictLimiter.middleware(), handler.RefreshSession)

	// Apply session auth middleware to protected routes
	sessionAuth := SessionAuthMiddleware(handler.Store)

	// --- User Security Events (Batch 1) ---
	route = router.Group("/users", securityHeadersMiddleware(), sessionAuth)
	route.Get("/:user_id/security-events", generalLimiter.middleware(), handler.ListUserSecurityEvents)
	route.Get("/:user_id/login-history", generalLimiter.middleware(), handler.ListUserLoginHistory)

	route.Post("/mfa/enable", strictLimiter.middleware(), handler.EnableMFA)
	route.Post("/mfa/disable", strictLimiter.middleware(), handler.DisableMFA)

	route.Post("/password/reset", strictLimiter.middleware(), handler.ResetUserPassword)

	route.Post("/sessions/create", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.CreateUserSession)
	route.Post("/sessions/delete", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.DeleteUserSession)
	route.Post("/sessions/get", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.GetUserSession)
	route.Get("/:user_id/sessions", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.ListUserSessions)
	route.Delete("/:user_id/sessions/:refresh_token", generalLimiter.middleware(), handler.RevokeUserSession)

	route.Get("/:user_id/api-keys", generalLimiter.middleware(), handler.ListUserAPIKeys)
	route.Post("/:user_id/api-keys", strictLimiter.middleware(), handler.CreateUserAPIKey)
	route.Delete("/:user_id/api-keys/:key_id", strictLimiter.middleware(), handler.RevokeUserAPIKey)

	route.Get("/:user_id/devices", generalLimiter.middleware(), handler.ListUserDevices)
	route.Delete("/:user_id/devices/:device_id", generalLimiter.middleware(), handler.RevokeUserDevice)

	// --- Audit Logs ---
	route = router.Group("/audit-logs", securityHeadersMiddleware(), sessionAuth)
	route.Post("/list", generalLimiter.middleware(), handler.ListSecurityAuditLogs)

	// --- Breaches ---
	route = router.Group("/breaches", securityHeadersMiddleware(), sessionAuth)
	route.Post("/list", generalLimiter.middleware(), handler.ListBreaches)

	// --- Security Policies ---
	route = router.Group("/policies", securityHeadersMiddleware(), sessionAuth)
	route.Get("/", generalLimiter.middleware(), handler.ListSecurityPolicies)
	route.Post("/", generalLimiter.middleware(), handler.CreateSecurityPolicy)
	route.Put("/:id", generalLimiter.middleware(), handler.UpdateSecurityPolicy)
	route.Delete("/:id", generalLimiter.middleware(), handler.DeleteSecurityPolicy)

	// --- Webhooks ---
	route = router.Group("/webhooks", securityHeadersMiddleware(), sessionAuth)
	route.Get("/:tenant_id", generalLimiter.middleware(), handler.ListWebhooks)
	route.Post("/:tenant_id", generalLimiter.middleware(), handler.CreateWebhook)
	route.Delete("/:tenant_id/:id", strictLimiter.middleware(), handler.DeleteWebhook)
	route.Post("/trigger", strictLimiter.middleware(), handler.TriggerWebhook)

	// --- Password Reset ---
	// Password reset should be open without session auth
	route = router.Group("/password-reset", securityHeadersMiddleware())
	route.Post("/request", strictLimiter.middleware(), handler.RequestPasswordResetToken)
	route.Post("/verify", strictLimiter.middleware(), handler.VerifyPasswordResetToken)
	route.Post("/use", strictLimiter.middleware(), handler.UsePasswordResetToken)

	// --- Rate Limit ---
	route = router.Group("/rate-limit", securityHeadersMiddleware(), sessionAuth)
	route.Post("/set", strictLimiter.middleware(), handler.SetRateLimit)
	route.Get("/get", strictLimiter.middleware(), handler.GetRateLimit)
	route.Post("/delete", strictLimiter.middleware(), handler.DeleteRateLimit)
	route.Get("/config", generalLimiter.middleware(), handler.GetRateLimitConfig)
	route.Post("/config", strictLimiter.middleware(), handler.SetRateLimitConfig)

	// --- Profile ---
	route = router.Group("/profile", securityHeadersMiddleware(), sessionAuth)
	route.Post("/get", generalLimiter.middleware(), handler.GetProfile)
	route.Post("/update", generalLimiter.middleware(), handler.UpdateProfile)

	// --- Account ---
	route = router.Group("/account", securityHeadersMiddleware(), sessionAuth)
	route.Post("/delete", strictLimiter.middleware(), handler.DeleteAccount)
	route.Post("/recover", strictLimiter.middleware(), handler.AccountRecover)

	// --- Consent ---
	route.Post("/consent", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.Consent)

	// --- MFA ---
	route = router.Group("/mfa", securityHeadersMiddleware(), sessionAuth)
	route.Post("/challenge", strictLimiter.middleware(), handler.MFAChallenge)
	route.Post("/verify", strictLimiter.middleware(), handler.MFAVerify)
	route.Get("/config", generalLimiter.middleware(), handler.GetMFAConfig)
	route.Post("/config", strictLimiter.middleware(), handler.SetMFAConfig)

	// --- Invite ---
	route = router.Group("/invite", securityHeadersMiddleware())
	route.Post("/send", sessionAuth, strictLimiter.middleware(), handler.SendInvite)
	route.Post("/accept", generalLimiter.middleware(), handler.AcceptInvite) // Accept invite doesn't need session auth

	// --- Device ---
	route = router.Group("/device", securityHeadersMiddleware(), sessionAuth)
	route.Post("/trust", strictLimiter.middleware(), handler.TrustDevice)

	// --- Notification ---
	route = router.Group("/notification", securityHeadersMiddleware())
	route.Get("/providers/status", handler.GetNotificationProvidersStatus)
	route.Post("/queue/retry", handler.RetryNotificationQueue)
	route.Get("/config", generalLimiter.middleware(), handler.GetNotificationConfig)
	route.Post("/config", strictLimiter.middleware(), handler.UpdateNotificationConfig)
	route.Post("/test", strictLimiter.middleware(), handler.SendTestNotification)
	route.Post("/channel/enabled", strictLimiter.middleware(), handler.SetNotificationChannelEnabled)
	route.Get("/channel/enabled", generalLimiter.middleware(), handler.GetNotificationChannelEnabled)
	route.Post("/provider/config", strictLimiter.middleware(), handler.SetProviderConfig)
	route.Get("/provider/config", generalLimiter.middleware(), handler.GetProviderConfig)

	// --- Module Config ---
	route = router.Group("/module", securityHeadersMiddleware())
	route.Post("/config", strictLimiter.middleware(), handler.SetSecurityModuleConfig)
	route.Get("/config", generalLimiter.middleware(), handler.GetSecurityModuleConfig)

	// --- Password Policy ---
	route = router.Group("/password-policy", securityHeadersMiddleware())
	route.Get("/config", generalLimiter.middleware(), handler.GetPasswordPolicyConfig)
	route.Post("/config", strictLimiter.middleware(), handler.SetPasswordPolicyConfig)

	// --- Session Config ---
	route = router.Group("/session", securityHeadersMiddleware())
	route.Get("/config", generalLimiter.middleware(), handler.GetSessionConfig)
	route.Post("/config", strictLimiter.middleware(), handler.SetSessionConfig)

	// --- Self Service ---
	route = router.Group("/self-service", securityHeadersMiddleware())
	route.Get("/", generalLimiter.middleware(), handler.GetSelfServiceSecurity)
}
