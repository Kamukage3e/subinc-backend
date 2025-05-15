package security_management

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// Architectural decision: All security-management endpoints use in-memory rate limiting and strict security headers.
// Sensitive endpoints have stricter limits.
func RegisterRoutes(router fiber.Router, handler *SecurityHandler, jwtSecretName string, auditLogger AuditLogger) {
	// General rate limiter: 30 req/min/IP
	generalLimiter := newInMemoryRateLimiter(30, time.Minute)
	// Sensitive: 10 req/min/IP
	strictLimiter := newInMemoryRateLimiter(10, time.Minute)

	// --- Bootstrap Owner Admin Resource ---
	// This route must be protected and only accessible when no users exist
	route := router.Group("/bootstrap", securityHeadersMiddleware())
	route.Post("/admin", strictLimiter.middleware(), handler.BootstrapOwnerAdmin)

	// --- Auth Resource ---
	route = router.Group("/auth", securityHeadersMiddleware())
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

	// --- Users Resource ---
	route = router.Group("/users", securityHeadersMiddleware(), sessionAuth)
	// Security events
	route.Get("/:user_id/security-events", generalLimiter.middleware(), handler.ListUserSecurityEvents)
	route.Get("/:user_id/security-events/:event_id", generalLimiter.middleware(), handler.GetUserSecurityEvent)
	route.Get("/:user_id/login-history", generalLimiter.middleware(), handler.ListUserLoginHistory)
	route.Get("/:user_id/login-history/:history_id", generalLimiter.middleware(), handler.GetUserLoginHistoryItem)

	// API Keys
	route.Get("/:user_id/api-keys", generalLimiter.middleware(), handler.ListUserAPIKeys)
	route.Post("/:user_id/api-keys", strictLimiter.middleware(), handler.CreateUserAPIKey)
	route.Delete("/:user_id/api-keys/:key_id", strictLimiter.middleware(), handler.RevokeUserAPIKey)

	// Devices
	route.Get("/:user_id/devices", generalLimiter.middleware(), handler.ListUserDevices)
	route.Delete("/:user_id/devices/:device_id", generalLimiter.middleware(), handler.RevokeUserDevice)
	route.Put("/:user_id/devices/:device_id/trust", strictLimiter.middleware(), handler.TrustDevice)

	// Sessions
	route.Get("/:user_id/sessions", generalLimiter.middleware(), handler.ListUserSessions)
	route.Post("/:user_id/sessions", generalLimiter.middleware(), handler.CreateUserSession)
	route.Get("/:user_id/sessions/:session_id", generalLimiter.middleware(), handler.GetUserSession)
	route.Delete("/:user_id/sessions/:session_id", generalLimiter.middleware(), handler.DeleteUserSession)
	route.Delete("/:user_id/sessions/:session_id/revoke", generalLimiter.middleware(), handler.RevokeUserSession)

	// MFA
	route.Get("/:user_id/mfa", generalLimiter.middleware(), handler.GetMFAConfig)
	route.Put("/:user_id/mfa", strictLimiter.middleware(), handler.EnableMFA)
	route.Delete("/:user_id/mfa", strictLimiter.middleware(), handler.DisableMFA)
	route.Get("/:user_id/mfa/challenge", strictLimiter.middleware(), handler.MFAChallenge)
	route.Post("/:user_id/mfa/verify", strictLimiter.middleware(), handler.MFAVerify)

	// Profile
	route.Get("/me", generalLimiter.middleware(), handler.GetProfile)            // Current user profile
	route.Put("/me", generalLimiter.middleware(), handler.UpdateProfile)         // Current user profile updates
	route.Delete("/me", strictLimiter.middleware(), handler.DeleteAccount)       // Current user account deletion
	route.Get("/:user_id", generalLimiter.middleware(), handler.GetProfile)      // Admin access to user profile
	route.Put("/:user_id", generalLimiter.middleware(), handler.UpdateProfile)   // Admin update of user profile
	route.Delete("/:user_id", strictLimiter.middleware(), handler.DeleteAccount) // Admin deletion of user
	route.Post("/recover", strictLimiter.middleware(), handler.AccountRecover)
	route.Post("/consent", generalLimiter.middleware(), handler.Consent)

	// Password
	route.Post("/:user_id/password/reset", strictLimiter.middleware(), handler.ResetUserPassword)

	// --- Audit Logs Resource ---
	route = router.Group("/audit-logs", securityHeadersMiddleware(), sessionAuth)
	route.Get("/", generalLimiter.middleware(), handler.ListSecurityAuditLogs)
	route.Get("/:log_id", generalLimiter.middleware(), handler.GetSecurityAuditLog)

	// --- Breaches Resource ---
	route = router.Group("/breaches", securityHeadersMiddleware(), sessionAuth)
	route.Get("/", generalLimiter.middleware(), handler.ListBreaches)
	route.Get("/:breach_id", generalLimiter.middleware(), handler.GetBreach)

	// --- Policies Resource ---
	route = router.Group("/policies", securityHeadersMiddleware(), sessionAuth)
	route.Get("/", generalLimiter.middleware(), handler.ListSecurityPolicies)
	route.Post("/", generalLimiter.middleware(), handler.CreateSecurityPolicy)
	route.Put("/:policy_id", generalLimiter.middleware(), handler.UpdateSecurityPolicy)
	route.Delete("/:policy_id", generalLimiter.middleware(), handler.DeleteSecurityPolicy)

	// --- Webhooks Resource ---
	route = router.Group("/webhooks", securityHeadersMiddleware(), sessionAuth)
	route.Get("/tenants/:tenant_id", generalLimiter.middleware(), handler.ListWebhooks)
	route.Post("/tenants/:tenant_id", generalLimiter.middleware(), handler.CreateWebhook)
	route.Delete("/tenants/:tenant_id/:webhook_id", strictLimiter.middleware(), handler.DeleteWebhook)
	route.Post("/tenants/:tenant_id/:webhook_id/trigger", strictLimiter.middleware(), handler.TriggerWebhook)

	// --- Password Reset Resource ---
	// Password reset should be open without session auth
	route = router.Group("/password-reset", securityHeadersMiddleware())
	route.Post("/request", strictLimiter.middleware(), handler.RequestPasswordResetToken)
	route.Post("/tokens/:token/verify", strictLimiter.middleware(), handler.VerifyPasswordResetToken)
	route.Post("/tokens/:token/redeem", strictLimiter.middleware(), handler.UsePasswordResetToken)

	// --- Rate Limits Resource ---
	route = router.Group("/rate-limits", securityHeadersMiddleware(), sessionAuth)
	route.Get("/:scope/:scope_id", strictLimiter.middleware(), handler.GetRateLimit)
	route.Put("/:scope/:scope_id", strictLimiter.middleware(), handler.SetRateLimit)
	route.Delete("/:rate_limit_id", strictLimiter.middleware(), handler.DeleteRateLimit)

	// --- Invite Resource ---
	route = router.Group("/invites", securityHeadersMiddleware())
	route.Post("/", sessionAuth, strictLimiter.middleware(), handler.SendInvite)
	route.Post("/accept", generalLimiter.middleware(), handler.AcceptInvite) // Accept invite doesn't need session auth

	// --- Notifications Resource ---
	route = router.Group("/notifications", securityHeadersMiddleware())
	route.Get("/providers/status", handler.GetNotificationProvidersStatus)
	route.Post("/queue/retry", handler.RetryNotificationQueue)
	route.Get("/tenants/:tenant_id/config", generalLimiter.middleware(), handler.GetNotificationConfig)
	route.Put("/tenants/:tenant_id/config", strictLimiter.middleware(), handler.UpdateNotificationConfig)
	route.Post("/tenants/:tenant_id/test", strictLimiter.middleware(), handler.SendTestNotification)
	route.Get("/tenants/:tenant_id/channels/:channel/providers/:provider/status", generalLimiter.middleware(), handler.GetNotificationChannelEnabled)
	route.Put("/tenants/:tenant_id/channels/:channel/providers/:provider/status", strictLimiter.middleware(), handler.SetNotificationChannelEnabled)
	route.Get("/tenants/:tenant_id/providers/:provider/config", generalLimiter.middleware(), handler.GetProviderConfig)
	route.Put("/tenants/:tenant_id/providers/:provider/config", strictLimiter.middleware(), handler.SetProviderConfig)

	// --- Config Resources ---
	// Module config
	route = router.Group("/configs", securityHeadersMiddleware())
	route.Get("/tenants/:tenant_id/security", generalLimiter.middleware(), handler.GetSecurityModuleConfig)
	route.Put("/tenants/:tenant_id/security", strictLimiter.middleware(), handler.SetSecurityModuleConfig)

	// Password policy
	route.Get("/tenants/:tenant_id/password-policy", generalLimiter.middleware(), handler.GetPasswordPolicyConfig)
	route.Put("/tenants/:tenant_id/password-policy", strictLimiter.middleware(), handler.SetPasswordPolicyConfig)

	// Session config
	route.Get("/tenants/:tenant_id/session", generalLimiter.middleware(), handler.GetSessionConfig)
	route.Put("/tenants/:tenant_id/session", strictLimiter.middleware(), handler.SetSessionConfig)

	// --- Self Service Resource ---
	route = router.Group("/self-service", securityHeadersMiddleware())
	route.Get("/security", generalLimiter.middleware(), handler.GetSelfServiceSecurity)

	// --- Security Analytics Resource ---
	route = router.Group("/analytics", securityHeadersMiddleware(), sessionAuth)
	route.Get("/tenants/:tenant_id/security", generalLimiter.middleware(), handler.GetSecurityAnalytics)
	route.Get("/tenants/:tenant_id/anomalies", generalLimiter.middleware(), handler.ListAnomalies)
	route.Get("/tenants/:tenant_id/anomalies/:anomaly_id", generalLimiter.middleware(), handler.GetAnomaly)
}
