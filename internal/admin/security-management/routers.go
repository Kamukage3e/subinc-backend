package security_management

import (
	"time"

	"github.com/gofiber/fiber/v2"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
	// "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
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
	route.Post("/admin", rbacmiddleware.RBACMiddleware("bootstrap", "create", nil), strictLimiter.middleware(), handler.BootstrapOwnerAdmin)

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
	route.Post("/token/refresh", rbacmiddleware.RBACMiddleware("session", "create", nil), strictLimiter.middleware(), handler.RefreshSession)

	// Apply session auth middleware to protected routes
	sessionAuth := SessionAuthMiddleware(handler.Store)

	// --- Users Resource ---
	route = router.Group("/users", securityHeadersMiddleware(), sessionAuth)
	// Security events
	route.Get("/:user_id/security-events", rbacmiddleware.RBACMiddleware("security-event", "read", nil), generalLimiter.middleware(), handler.ListUserSecurityEvents)
	route.Get("/:user_id/security-events/:event_id", rbacmiddleware.RBACMiddleware("security-event", "read", nil), generalLimiter.middleware(), handler.GetUserSecurityEvent)
	route.Get("/:user_id/login-history", rbacmiddleware.RBACMiddleware("login-history", "read", nil), generalLimiter.middleware(), handler.ListUserLoginHistory)
	route.Get("/:user_id/login-history/:history_id", rbacmiddleware.RBACMiddleware("login-history", "read", nil), generalLimiter.middleware(), handler.GetUserLoginHistoryItem)

	// API Keys
	route.Get("/:user_id/api-keys", rbacmiddleware.RBACMiddleware("api-key", "read", nil), generalLimiter.middleware(), handler.ListUserAPIKeys)
	route.Post("/:user_id/api-keys", rbacmiddleware.RBACMiddleware("api-key", "create", nil), strictLimiter.middleware(), handler.CreateUserAPIKey)
	route.Delete("/:user_id/api-keys/:key_id", rbacmiddleware.RBACMiddleware("api-key", "delete", nil), strictLimiter.middleware(), handler.RevokeUserAPIKey)

	// Devices
	route.Get("/:user_id/devices", rbacmiddleware.RBACMiddleware("device", "read", nil), generalLimiter.middleware(), handler.ListUserDevices)
	route.Delete("/:user_id/devices/:device_id", rbacmiddleware.RBACMiddleware("device", "delete", nil), generalLimiter.middleware(), handler.RevokeUserDevice)
	route.Put("/:user_id/devices/:device_id/trust", rbacmiddleware.RBACMiddleware("device", "update", nil), strictLimiter.middleware(), handler.TrustDevice)

	// Sessions
	route.Get("/:user_id/sessions", rbacmiddleware.RBACMiddleware("session", "read", nil), generalLimiter.middleware(), handler.ListUserSessions)
	route.Post("/:user_id/sessions", rbacmiddleware.RBACMiddleware("session", "create", nil), generalLimiter.middleware(), handler.CreateUserSession)
	route.Get("/:user_id/sessions/:session_id", rbacmiddleware.RBACMiddleware("session", "read", nil), generalLimiter.middleware(), handler.GetUserSession)
	route.Delete("/:user_id/sessions/:session_id", rbacmiddleware.RBACMiddleware("session", "delete", nil), generalLimiter.middleware(), handler.DeleteUserSession)
	route.Delete("/:user_id/sessions/:session_id/revoke", rbacmiddleware.RBACMiddleware("session", "delete", nil), generalLimiter.middleware(), handler.RevokeUserSession)

	// MFA
	route.Get("/:user_id/mfa", rbacmiddleware.RBACMiddleware("mfa", "read", nil), generalLimiter.middleware(), handler.GetMFAConfig)
	route.Put("/:user_id/mfa", rbacmiddleware.RBACMiddleware("mfa", "update", nil), strictLimiter.middleware(), handler.EnableMFA)
	route.Delete("/:user_id/mfa", rbacmiddleware.RBACMiddleware("mfa", "delete", nil), strictLimiter.middleware(), handler.DisableMFA)
	route.Get("/:user_id/mfa/challenge", rbacmiddleware.RBACMiddleware("mfa", "read", nil), strictLimiter.middleware(), handler.MFAChallenge)
	route.Post("/:user_id/mfa/verify", rbacmiddleware.RBACMiddleware("mfa", "create", nil), strictLimiter.middleware(), handler.MFAVerify)

	// Profile
	route.Get("/me", rbacmiddleware.RBACMiddleware("profile", "read", nil), generalLimiter.middleware(), handler.GetProfile)              // Current user profile
	route.Put("/me", rbacmiddleware.RBACMiddleware("profile", "update", nil), generalLimiter.middleware(), handler.UpdateProfile)         // Current user profile updates
	route.Delete("/me", rbacmiddleware.RBACMiddleware("profile", "delete", nil), strictLimiter.middleware(), handler.DeleteAccount)       // Current user account deletion
	route.Get("/:user_id", rbacmiddleware.RBACMiddleware("profile", "read", nil), generalLimiter.middleware(), handler.GetProfile)        // Admin access to user profile
	route.Put("/:user_id", rbacmiddleware.RBACMiddleware("profile", "update", nil), generalLimiter.middleware(), handler.UpdateProfile)   // Admin update of user profile
	route.Delete("/:user_id", rbacmiddleware.RBACMiddleware("profile", "delete", nil), strictLimiter.middleware(), handler.DeleteAccount) // Admin deletion of user
	route.Post("/recover", rbacmiddleware.RBACMiddleware("profile", "create", nil), strictLimiter.middleware(), handler.AccountRecover)
	route.Post("/consent", rbacmiddleware.RBACMiddleware("profile", "create", nil), generalLimiter.middleware(), handler.Consent)

	// Password
	route.Post("/:user_id/password/reset", rbacmiddleware.RBACMiddleware("password", "create", nil), strictLimiter.middleware(), handler.ResetUserPassword)

	// --- Audit Logs Resource ---
	route = router.Group("/audit-logs", securityHeadersMiddleware(), sessionAuth)
	route.Get("/", rbacmiddleware.RBACMiddleware("audit-log", "read", nil), generalLimiter.middleware(), handler.ListSecurityAuditLogs)
	route.Get("/:log_id", rbacmiddleware.RBACMiddleware("audit-log", "read", nil), generalLimiter.middleware(), handler.GetSecurityAuditLog)

	// --- Breaches Resource ---
	route = router.Group("/breaches", securityHeadersMiddleware(), sessionAuth)
	route.Get("/", rbacmiddleware.RBACMiddleware("breach", "read", nil), generalLimiter.middleware(), handler.ListBreaches)
	route.Get("/:breach_id", rbacmiddleware.RBACMiddleware("breach", "read", nil), generalLimiter.middleware(), handler.GetBreach)

	// --- Policies Resource ---
	route = router.Group("/policies", securityHeadersMiddleware(), sessionAuth)
	route.Get("/", rbacmiddleware.RBACMiddleware("policy", "read", nil), generalLimiter.middleware(), handler.ListSecurityPolicies)
	route.Post("/", rbacmiddleware.RBACMiddleware("policy", "create", nil), generalLimiter.middleware(), handler.CreateSecurityPolicy)
	route.Put("/:policy_id", rbacmiddleware.RBACMiddleware("policy", "update", nil), generalLimiter.middleware(), handler.UpdateSecurityPolicy)
	route.Delete("/:policy_id", rbacmiddleware.RBACMiddleware("policy", "delete", nil), generalLimiter.middleware(), handler.DeleteSecurityPolicy)

	// --- Webhooks Resource ---
	route = router.Group("/webhooks", securityHeadersMiddleware(), sessionAuth)
	route.Get("/tenants/:tenant_id", rbacmiddleware.RBACMiddleware("webhook", "read", nil), generalLimiter.middleware(), handler.ListWebhooks)
	route.Post("/tenants/:tenant_id", rbacmiddleware.RBACMiddleware("webhook", "create", nil), generalLimiter.middleware(), handler.CreateWebhook)
	route.Delete("/tenants/:tenant_id/:webhook_id", rbacmiddleware.RBACMiddleware("webhook", "delete", nil), generalLimiter.middleware(), handler.DeleteWebhook)
	route.Post("/tenants/:tenant_id/:webhook_id/trigger", rbacmiddleware.RBACMiddleware("webhook", "create", nil), generalLimiter.middleware(), handler.TriggerWebhook)

	// --- Password Reset Resource ---
	// Password reset should be open without session auth
	route = router.Group("/password-reset", securityHeadersMiddleware())
	route.Post("/request", rbacmiddleware.RBACMiddleware("password-reset", "create", nil), strictLimiter.middleware(), handler.RequestPasswordResetToken)
	route.Post("/tokens/:token/verify", rbacmiddleware.RBACMiddleware("password-reset", "create", nil), strictLimiter.middleware(), handler.VerifyPasswordResetToken)
	route.Post("/tokens/:token/redeem", rbacmiddleware.RBACMiddleware("password-reset", "create", nil), strictLimiter.middleware(), handler.UsePasswordResetToken)

	// --- Rate Limits Resource ---
	route = router.Group("/rate-limits", securityHeadersMiddleware(), sessionAuth)
	route.Get("/:scope/:scope_id", rbacmiddleware.RBACMiddleware("rate-limit", "read", nil), strictLimiter.middleware(), handler.GetRateLimit)
	route.Put("/:scope/:scope_id", rbacmiddleware.RBACMiddleware("rate-limit", "update", nil), strictLimiter.middleware(), handler.SetRateLimit)
	route.Delete("/:rate_limit_id", rbacmiddleware.RBACMiddleware("rate-limit", "delete", nil), strictLimiter.middleware(), handler.DeleteRateLimit)

	// --- Invite Resource ---
	route = router.Group("/invites", securityHeadersMiddleware())
	route.Post("/", sessionAuth, rbacmiddleware.RBACMiddleware("invite", "create", nil), strictLimiter.middleware(), handler.SendInvite)
	route.Post("/accept", rbacmiddleware.RBACMiddleware("invite", "create", nil), generalLimiter.middleware(), handler.AcceptInvite) // Accept invite doesn't need session auth

	// --- Notifications Resource ---
	route = router.Group("/notifications", securityHeadersMiddleware())
	route.Get("/providers/status", rbacmiddleware.RBACMiddleware("notification", "read", nil), handler.GetNotificationProvidersStatus)
	route.Post("/queue/retry", rbacmiddleware.RBACMiddleware("notification", "create", nil), handler.RetryNotificationQueue)
	route.Get("/tenants/:tenant_id/config", rbacmiddleware.RBACMiddleware("notification", "read", nil), generalLimiter.middleware(), handler.GetNotificationConfig)
	route.Put("/tenants/:tenant_id/config", rbacmiddleware.RBACMiddleware("notification", "update", nil), strictLimiter.middleware(), handler.UpdateNotificationConfig)
	route.Post("/tenants/:tenant_id/test", rbacmiddleware.RBACMiddleware("notification", "create", nil), strictLimiter.middleware(), handler.SendTestNotification)
	route.Get("/tenants/:tenant_id/channels/:channel/providers/:provider/status", rbacmiddleware.RBACMiddleware("notification", "read", nil), generalLimiter.middleware(), handler.GetNotificationChannelEnabled)
	route.Put("/tenants/:tenant_id/channels/:channel/providers/:provider/status", rbacmiddleware.RBACMiddleware("notification", "update", nil), strictLimiter.middleware(), handler.SetNotificationChannelEnabled)
	route.Get("/tenants/:tenant_id/providers/:provider/config", rbacmiddleware.RBACMiddleware("notification", "read", nil), generalLimiter.middleware(), handler.GetProviderConfig)
	route.Put("/tenants/:tenant_id/providers/:provider/config", rbacmiddleware.RBACMiddleware("notification", "update", nil), strictLimiter.middleware(), handler.SetProviderConfig)

	// --- Config Resources ---
	// Module config
	route = router.Group("/configs", securityHeadersMiddleware())
	route.Get("/tenants/:tenant_id/security", rbacmiddleware.RBACMiddleware("config", "read", nil), generalLimiter.middleware(), handler.GetSecurityModuleConfig)
	route.Put("/tenants/:tenant_id/security", rbacmiddleware.RBACMiddleware("config", "update", nil), strictLimiter.middleware(), handler.SetSecurityModuleConfig)

	// Password policy
	route.Get("/tenants/:tenant_id/password-policy", rbacmiddleware.RBACMiddleware("config", "read", nil), generalLimiter.middleware(), handler.GetPasswordPolicyConfig)
	route.Put("/tenants/:tenant_id/password-policy", rbacmiddleware.RBACMiddleware("config", "update", nil), strictLimiter.middleware(), handler.SetPasswordPolicyConfig)

	// Session config
	route.Get("/tenants/:tenant_id/session", rbacmiddleware.RBACMiddleware("config", "read", nil), generalLimiter.middleware(), handler.GetSessionConfig)
	route.Put("/tenants/:tenant_id/session", rbacmiddleware.RBACMiddleware("config", "update", nil), strictLimiter.middleware(), handler.SetSessionConfig)

	// --- Self Service Resource ---
	route = router.Group("/self-service", securityHeadersMiddleware())
	route.Get("/security", rbacmiddleware.RBACMiddleware("self-service", "read", nil), generalLimiter.middleware(), handler.GetSelfServiceSecurity)

	// --- Security Analytics Resource ---
	route = router.Group("/analytics", securityHeadersMiddleware(), sessionAuth)
	route.Get("/tenants/:tenant_id/security", rbacmiddleware.RBACMiddleware("analytics", "read", nil), generalLimiter.middleware(), handler.GetSecurityAnalytics)
	route.Get("/tenants/:tenant_id/anomalies", rbacmiddleware.RBACMiddleware("analytics", "read", nil), generalLimiter.middleware(), handler.ListAnomalies)
	route.Get("/tenants/:tenant_id/anomalies/:anomaly_id", rbacmiddleware.RBACMiddleware("analytics", "read", nil), generalLimiter.middleware(), handler.GetAnomaly)
}
