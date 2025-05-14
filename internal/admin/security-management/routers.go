package security_management

import (
	"time"

	"github.com/gofiber/fiber/v2"

)

// Architectural decision: All security-management endpoints use in-memory rate limiting and strict security headers.
// Sensitive endpoints have stricter limits.
func RegisterAdminSecurityRoutes(router fiber.Router, handler *SecurityHandler, jwtSecretName string, auditLogger AuditLogger) {
	// General rate limiter: 30 req/min/IP
	generalLimiter := newInMemoryRateLimiter(30, time.Minute)
	// Sensitive: 10 req/min/IP
	strictLimiter := newInMemoryRateLimiter(10, time.Minute)

	// --- Auth ---
	auth := router.Group("/auth", securityHeadersMiddleware(), )
	auth.Post("/login", strictLimiter.middleware(), handler.Login)
	auth.Post("/logout", strictLimiter.middleware(), handler.Logout)
	auth.Post("/register", generalLimiter.middleware(), handler.Register)
	auth.Post("/verify-email", generalLimiter.middleware(), handler.VerifyEmail)
	auth.Post("/resend-verification", generalLimiter.middleware(), handler.ResendVerification)
	auth.Post("/change-password", strictLimiter.middleware(), handler.ChangePassword)
	auth.Get("/google", strictLimiter.middleware(), handler.AuthGoogle)
	auth.Get("/google/callback", strictLimiter.middleware(), handler.AuthGoogleCallback)
	auth.Get("/saml", strictLimiter.middleware(), handler.AuthSAML)
	auth.Get("/saml/callback", strictLimiter.middleware(), handler.AuthSAMLCallback)
	auth.Post("/token/refresh", strictLimiter.middleware(), handler.RefreshSession)

	// Apply session auth middleware to protected routes
	sessionAuth := SessionAuthMiddleware(handler.Store)

	// --- User Security Events ---
	user := router.Group("/users", securityHeadersMiddleware(), sessionAuth)
	user.Post("/security-events", generalLimiter.middleware(), handler.ListUserSecurityEvents)
	user.Post("/login-history", generalLimiter.middleware(), handler.ListUserLoginHistory)
	user.Post("/mfa/enable", strictLimiter.middleware(), handler.EnableMFA)
	user.Post("/mfa/disable", strictLimiter.middleware(), handler.DisableMFA)
	user.Post("/password/reset", strictLimiter.middleware(), handler.ResetUserPassword)
	user.Post("/sessions/create", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.CreateUserSession)
	user.Post("/sessions/delete", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.DeleteUserSession)
	user.Post("/sessions/get", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.GetUserSession)
	user.Post("/sessions/list", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.ListUserSessions)
	user.Post("/sessions/revoke", generalLimiter.middleware(), handler.RevokeUserSession)
	user.Post("/api-keys/list", generalLimiter.middleware(), handler.ListUserAPIKeys)
	user.Post("/api-keys/create", strictLimiter.middleware(), handler.CreateUserAPIKey)
	user.Post("/api-keys/revoke", strictLimiter.middleware(), handler.RevokeUserAPIKey)
	user.Post("/devices/list", generalLimiter.middleware(), handler.ListUserDevices)
	user.Post("/devices/revoke", generalLimiter.middleware(), handler.RevokeUserDevice)

	// --- Audit Logs ---
	audit := router.Group("/audit-logs", securityHeadersMiddleware(), sessionAuth)
	audit.Post("/list", generalLimiter.middleware(), handler.ListSecurityAuditLogs)

	// --- Breaches ---
	breaches := router.Group("/breaches", securityHeadersMiddleware(), sessionAuth)
	breaches.Post("/list", generalLimiter.middleware(), handler.ListBreaches)

	// --- Security Policies ---
	policies := router.Group("/policies", securityHeadersMiddleware(), sessionAuth)
	policies.Post("/list", generalLimiter.middleware(), handler.ListSecurityPolicies)
	policies.Post("/create", generalLimiter.middleware(), handler.CreateSecurityPolicy)
	policies.Post("/update", generalLimiter.middleware(), handler.UpdateSecurityPolicy)
	policies.Post("/delete", generalLimiter.middleware(), handler.DeleteSecurityPolicy)

	// --- Webhooks ---
	webhooks := router.Group("/webhooks", securityHeadersMiddleware(), sessionAuth)
	webhooks.Post("/create", generalLimiter.middleware(), handler.CreateWebhook)
	webhooks.Post("/list", generalLimiter.middleware(), handler.ListWebhooks)
	webhooks.Post("/delete", strictLimiter.middleware(), handler.DeleteWebhook)
	webhooks.Post("/trigger", strictLimiter.middleware(), handler.TriggerWebhook)

	// --- Password Reset ---
	// Password reset should be open without session auth
	passwordReset := router.Group("/password-reset", securityHeadersMiddleware())
	passwordReset.Post("/request", strictLimiter.middleware(), handler.RequestPasswordResetToken)
	passwordReset.Post("/verify", strictLimiter.middleware(), handler.VerifyPasswordResetToken)
	passwordReset.Post("/use", strictLimiter.middleware(), handler.UsePasswordResetToken)

	// --- Rate Limit ---
	rateLimit := router.Group("/rate-limit", securityHeadersMiddleware(), sessionAuth)
	rateLimit.Post("/set", strictLimiter.middleware(), handler.SetRateLimit)
	rateLimit.Get("/get", strictLimiter.middleware(), handler.GetRateLimit)
	rateLimit.Post("/delete", strictLimiter.middleware(), handler.DeleteRateLimit)
	rateLimit.Get("/config", generalLimiter.middleware(), handler.GetRateLimitConfig)
	rateLimit.Post("/config", strictLimiter.middleware(), handler.SetRateLimitConfig)

	// --- Profile ---
	profile := router.Group("/profile", securityHeadersMiddleware(), sessionAuth)
	profile.Post("/get", generalLimiter.middleware(), handler.GetProfile)
	profile.Post("/update", generalLimiter.middleware(), handler.UpdateProfile)

	// --- Account ---
	account := router.Group("/account", securityHeadersMiddleware(), sessionAuth)
	account.Post("/delete", strictLimiter.middleware(), handler.DeleteAccount)
	account.Post("/recover", strictLimiter.middleware(), handler.AccountRecover)

	// --- Consent ---
	router.Post("/consent", securityHeadersMiddleware(), sessionAuth, generalLimiter.middleware(), handler.Consent)

	// --- MFA ---
	mfa := router.Group("/mfa", securityHeadersMiddleware(), sessionAuth)
	mfa.Post("/challenge", strictLimiter.middleware(), handler.MFAChallenge)
	mfa.Post("/verify", strictLimiter.middleware(), handler.MFAVerify)
	mfa.Get("/config", generalLimiter.middleware(), handler.GetMFAConfig)
	mfa.Post("/config", strictLimiter.middleware(), handler.SetMFAConfig)

	// --- Invite ---
	invite := router.Group("/invite", securityHeadersMiddleware())
	invite.Post("/send", sessionAuth, strictLimiter.middleware(), handler.SendInvite)
	invite.Post("/accept", generalLimiter.middleware(), handler.AcceptInvite) // Accept invite doesn't need session auth

	// --- Device ---
	device := router.Group("/device", securityHeadersMiddleware(), sessionAuth)
	device.Post("/trust", strictLimiter.middleware(), handler.TrustDevice)

	// --- Notification ---
	notification := router.Group("/notification", securityHeadersMiddleware())
	notification.Get("/providers/status", handler.GetNotificationProvidersStatus)
	notification.Post("/queue/retry", handler.RetryNotificationQueue)
	notification.Get("/config", generalLimiter.middleware(), handler.GetNotificationConfig)
	notification.Post("/config", strictLimiter.middleware(), handler.UpdateNotificationConfig)
	notification.Post("/test", strictLimiter.middleware(), handler.SendTestNotification)
	notification.Post("/channel/enabled", strictLimiter.middleware(), handler.SetNotificationChannelEnabled)
	notification.Get("/channel/enabled", generalLimiter.middleware(), handler.GetNotificationChannelEnabled)
	notification.Post("/provider/config", strictLimiter.middleware(), handler.SetProviderConfig)
	notification.Get("/provider/config", generalLimiter.middleware(), handler.GetProviderConfig)

	// --- Module Config ---
	module := router.Group("/module", securityHeadersMiddleware())
	module.Post("/config", strictLimiter.middleware(), handler.SetSecurityModuleConfig)
	module.Get("/config", generalLimiter.middleware(), handler.GetSecurityModuleConfig)

	// --- Password Policy ---
	passwordPolicy := router.Group("/password-policy", securityHeadersMiddleware())
	passwordPolicy.Get("/config", generalLimiter.middleware(), handler.GetPasswordPolicyConfig)
	passwordPolicy.Post("/config", strictLimiter.middleware(), handler.SetPasswordPolicyConfig)

	// --- Session Config ---
	session := router.Group("/session", securityHeadersMiddleware())
	session.Get("/config", generalLimiter.middleware(), handler.GetSessionConfig)
	session.Post("/config", strictLimiter.middleware(), handler.SetSessionConfig)

	// --- Self Service ---
	router.Get("/self-service", securityHeadersMiddleware(), generalLimiter.middleware(), handler.GetSelfServiceSecurity)
}
