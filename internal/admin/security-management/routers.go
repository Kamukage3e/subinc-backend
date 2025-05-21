package security_management

import (
	"github.com/gofiber/fiber/v2"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

// Architectural decision: All security-management endpoints use security headers.
func RegisterRoutes(router fiber.Router, handler *SecurityHandler, jwtSecretName string) {
	// --- Bootstrap Owner Admin Resource ---
	// This route must be protected and only accessible when no users exist
	route := router.Group("/bootstrap", securityHeadersMiddleware())
	route.Post("/admin", rbacmiddleware.RBACMiddleware("bootstrap", "create", nil), handler.BootstrapOwnerAdmin)

	// --- Auth Resource ---
	route = router.Group("/auth", securityHeadersMiddleware())
	route.Post("/login", handler.Login)
	route.Post("/logout", handler.Logout)
	route.Post("/register", handler.Register)
	route.Post("/verify-email", handler.VerifyEmail)
	route.Post("/resend-verification", handler.ResendVerification)
	route.Post("/change-password", handler.ChangePassword)
	route.Get("/google", handler.AuthGoogle)
	route.Get("/google/callback", handler.AuthGoogleCallback)
	route.Get("/saml", handler.AuthSAML)
	route.Get("/saml/callback", handler.AuthSAMLCallback)
	route.Post("/token/refresh", rbacmiddleware.RBACMiddleware("session", "create", nil), handler.RefreshSession)

	// Apply session auth middleware to protected routes
	sessionAuth := SessionAuthMiddleware(handler.Store)

	// --- Users Resource ---
	route = router.Group("/users", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	// Security events
	route.Get("/:user_id/security-events", rbacmiddleware.RBACMiddleware("security-event", "read", nil), handler.ListUserSecurityEvents)
	route.Get("/:user_id/security-events/:event_id", rbacmiddleware.RBACMiddleware("security-event", "read", nil), handler.GetUserSecurityEvent)
	route.Get("/:user_id/login-history", rbacmiddleware.RBACMiddleware("login-history", "read", nil), handler.ListUserLoginHistory)
	route.Get("/:user_id/login-history/:history_id", rbacmiddleware.RBACMiddleware("login-history", "read", nil), handler.GetUserLoginHistoryItem)

	// API Keys
	route.Get("/:user_id/api-keys", rbacmiddleware.RBACMiddleware("api-key", "read", nil), handler.ListUserAPIKeys)
	route.Post("/:user_id/api-keys", rbacmiddleware.RBACMiddleware("api-key", "create", nil), handler.CreateUserAPIKey)
	route.Delete("/:user_id/api-keys/:key_id", rbacmiddleware.RBACMiddleware("api-key", "delete", nil), handler.RevokeUserAPIKey)

	// Devices
	route.Get("/:user_id/devices", rbacmiddleware.RBACMiddleware("device", "read", nil), handler.ListUserDevices)
	route.Delete("/:user_id/devices/:device_id", rbacmiddleware.RBACMiddleware("device", "delete", nil), handler.RevokeUserDevice)
	route.Put("/:user_id/devices/:device_id/trust", rbacmiddleware.RBACMiddleware("device", "update", nil), handler.TrustDevice)

	// Sessions
	route.Get("/:user_id/sessions", rbacmiddleware.RBACMiddleware("session", "read", nil), handler.ListUserSessions)
	route.Post("/:user_id/sessions", rbacmiddleware.RBACMiddleware("session", "create", nil), handler.CreateUserSession)
	route.Get("/:user_id/sessions/:session_id", rbacmiddleware.RBACMiddleware("session", "read", nil), handler.GetUserSession)
	route.Delete("/:user_id/sessions/:session_id", rbacmiddleware.RBACMiddleware("session", "delete", nil), handler.DeleteUserSession)
	route.Delete("/:user_id/sessions/:session_id/revoke", rbacmiddleware.RBACMiddleware("session", "delete", nil), handler.RevokeUserSession)

	// MFA
	route.Get("/:user_id/mfa", rbacmiddleware.RBACMiddleware("mfa", "read", nil), handler.GetMFAConfig)
	route.Put("/:user_id/mfa", rbacmiddleware.RBACMiddleware("mfa", "update", nil), handler.EnableMFA)
	route.Delete("/:user_id/mfa", rbacmiddleware.RBACMiddleware("mfa", "delete", nil), handler.DisableMFA)
	route.Get("/:user_id/mfa/challenge", rbacmiddleware.RBACMiddleware("mfa", "read", nil), handler.MFAChallenge)
	route.Post("/:user_id/mfa/verify", rbacmiddleware.RBACMiddleware("mfa", "create", nil), handler.MFAVerify)

	// Profile
	route.Get("/me", rbacmiddleware.RBACMiddleware("profile", "read", nil), handler.GetProfile)               // Current user profile
	route.Put("/me", rbacmiddleware.RBACMiddleware("profile", "update", nil), handler.UpdateProfile)          // Current user profile updates
	route.Delete("/me", rbacmiddleware.RBACMiddleware("profile", "delete", nil), handler.DeleteAccount)       // Current user account deletion
	route.Get("/:user_id", rbacmiddleware.RBACMiddleware("profile", "read", nil), handler.GetProfile)         // Admin access to user profile
	route.Put("/:user_id", rbacmiddleware.RBACMiddleware("profile", "update", nil), handler.UpdateProfile)    // Admin update of user profile
	route.Delete("/:user_id", rbacmiddleware.RBACMiddleware("profile", "delete", nil), handler.DeleteAccount) // Admin deletion of user
	route.Post("/recover", rbacmiddleware.RBACMiddleware("profile", "create", nil), handler.AccountRecover)
	route.Post("/consent", rbacmiddleware.RBACMiddleware("profile", "create", nil), handler.Consent)

	// Password
	route.Post("/:user_id/password/reset", rbacmiddleware.RBACMiddleware("password", "create", nil), handler.ResetUserPassword)

	// --- Breaches Resource ---
	route = router.Group("/breaches", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	route.Get("/", rbacmiddleware.RBACMiddleware("breach", "read", nil), handler.ListBreaches)
	route.Get("/:breach_id", rbacmiddleware.RBACMiddleware("breach", "read", nil), handler.GetBreach)

	// --- Policies Resource ---
	route = router.Group("/policies", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	route.Get("/", rbacmiddleware.RBACMiddleware("policy", "read", nil), handler.ListSecurityPolicies)
	route.Post("/", rbacmiddleware.RBACMiddleware("policy", "create", nil), handler.CreateSecurityPolicy)
	route.Put("/:policy_id", rbacmiddleware.RBACMiddleware("policy", "update", nil), handler.UpdateSecurityPolicy)
	route.Delete("/:policy_id", rbacmiddleware.RBACMiddleware("policy", "delete", nil), handler.DeleteSecurityPolicy)

	// --- Webhooks Resource ---
	route = router.Group("/webhooks", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	route.Get("/tenants/:tenant_id", rbacmiddleware.RBACMiddleware("webhook", "read", nil), handler.ListWebhooks)
	route.Post("/tenants/:tenant_id", rbacmiddleware.RBACMiddleware("webhook", "create", nil), handler.CreateWebhook)
	route.Delete("/tenants/:tenant_id/:webhook_id", rbacmiddleware.RBACMiddleware("webhook", "delete", nil), handler.DeleteWebhook)
	route.Post("/tenants/:tenant_id/:webhook_id/trigger", rbacmiddleware.RBACMiddleware("webhook", "create", nil), handler.TriggerWebhook)

	// --- Password Reset Resource ---
	// Password reset should be open without session auth
	route = router.Group("/password-reset", securityHeadersMiddleware())
	route.Post("/request", rbacmiddleware.RBACMiddleware("password-reset", "create", nil), handler.RequestPasswordResetToken)
	route.Post("/tokens/:token/verify", rbacmiddleware.RBACMiddleware("password-reset", "create", nil), handler.VerifyPasswordResetToken)
	route.Post("/tokens/:token/redeem", rbacmiddleware.RBACMiddleware("password-reset", "create", nil), handler.UsePasswordResetToken)

	// --- Invite Resource ---
	route = router.Group("/invites", securityHeadersMiddleware())
	route.Post("/", sessionAuth, rbacmiddleware.RBACMiddleware("invite", "create", nil), handler.SendInvite)
	route.Post("/accept", rbacmiddleware.RBACMiddleware("invite", "create", nil), handler.AcceptInvite) // Accept invite doesn't need session auth

	// --- Notifications Resource ---
	route = router.Group("/notifications", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	route.Get("/providers/status", rbacmiddleware.RBACMiddleware("notification", "read", nil), handler.GetNotificationProvidersStatus)
	route.Post("/queue/retry", rbacmiddleware.RBACMiddleware("notification", "create", nil), handler.RetryNotificationQueue)
	route.Get("/tenants/:tenant_id/config", rbacmiddleware.RBACMiddleware("notification", "read", nil), handler.GetNotificationConfig)
	route.Put("/tenants/:tenant_id/config", rbacmiddleware.RBACMiddleware("notification", "update", nil), handler.UpdateNotificationConfig)
	route.Post("/tenants/:tenant_id/test", rbacmiddleware.RBACMiddleware("notification", "create", nil), handler.SendTestNotification)
	route.Get("/tenants/:tenant_id/channels/:channel/providers/:provider/status", rbacmiddleware.RBACMiddleware("notification", "read", nil), handler.GetNotificationChannelEnabled)
	route.Put("/tenants/:tenant_id/channels/:channel/providers/:provider/status", rbacmiddleware.RBACMiddleware("notification", "update", nil), handler.SetNotificationChannelEnabled)
	route.Get("/tenants/:tenant_id/providers/:provider/config", rbacmiddleware.RBACMiddleware("notification", "read", nil), handler.GetProviderConfig)
	route.Put("/tenants/:tenant_id/providers/:provider/config", rbacmiddleware.RBACMiddleware("notification", "update", nil), handler.SetProviderConfig)

	// --- Config Resources ---
	// Module config
	route = router.Group("/configs", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	route.Get("/tenants/:tenant_id/security", rbacmiddleware.RBACMiddleware("config", "read", nil), handler.GetSecurityModuleConfig)
	route.Put("/tenants/:tenant_id/security", rbacmiddleware.RBACMiddleware("config", "update", nil), handler.SetSecurityModuleConfig)

	// Password policy
	route.Get("/tenants/:tenant_id/password-policy", rbacmiddleware.RBACMiddleware("config", "read", nil), handler.GetPasswordPolicyConfig)
	route.Put("/tenants/:tenant_id/password-policy", rbacmiddleware.RBACMiddleware("config", "update", nil), handler.SetPasswordPolicyConfig)

	// Session config
	route.Get("/tenants/:tenant_id/session", rbacmiddleware.RBACMiddleware("config", "read", nil), handler.GetSessionConfig)
	route.Put("/tenants/:tenant_id/session", rbacmiddleware.RBACMiddleware("config", "update", nil), handler.SetSessionConfig)

	// --- Self Service Resource ---
	route = router.Group("/self-service", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	route.Get("/security", rbacmiddleware.RBACMiddleware("self-service", "read", nil), handler.GetSelfServiceSecurity)

	// --- Security Analytics Resource ---
	route = router.Group("/analytics", securityHeadersMiddleware(), OIDCMiddleware(jwtSecretName))
	route.Get("/tenants/:tenant_id/security", rbacmiddleware.RBACMiddleware("analytics", "read", nil), handler.GetSecurityAnalytics)
	route.Get("/tenants/:tenant_id/anomalies", rbacmiddleware.RBACMiddleware("analytics", "read", nil), handler.ListAnomalies)
	route.Get("/tenants/:tenant_id/anomalies/:anomaly_id", rbacmiddleware.RBACMiddleware("analytics", "read", nil), handler.GetAnomaly)
}
