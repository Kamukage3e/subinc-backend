package server_config

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// RegisterAdminServerConfigRoutes registers admin API routes for server config management.
func RegisterAdminServerConfigRoutes(router fiber.Router, handler *Handler, jwtSecret string) {
	cfg := router.Group(
		"/server-config",
		security_management.OIDCMiddleware(jwtSecret),
	)
	cfg.Get("/list", handler.ListConfig)
	cfg.Get("/get/:key", handler.GetConfig)
	cfg.Post("/set", handler.SetConfig)
	cfg.Get("/history/:key", handler.ConfigHistory)

	// Add missing real handlers for migration status and config
	cfg.Get("/migration-status", handler.ListMigrationStatus)
	cfg.Get("/migration-status/:name", handler.GetMigrationStatus)
	cfg.Post("/migration-status", handler.SetMigrationStatus)

	cfg.Get("/owner-db-config", handler.GetOwnerDBConfig)
	cfg.Post("/owner-db-config", handler.SetOwnerDBConfig)

	cfg.Get("/owner-logging-config", handler.GetOwnerLoggingConfig)
	cfg.Post("/owner-logging-config", handler.SetOwnerLoggingConfig)

	cfg.Get("/owner-jwt-secret-config", handler.GetOwnerJWTSecretConfig)
	cfg.Post("/owner-jwt-secret-config", handler.SetOwnerJWTSecretConfig)

	cfg.Get("/owner-oauth-config", handler.GetOwnerOAuthConfig)
	cfg.Post("/owner-oauth-config", handler.SetOwnerOAuthConfig)
	cfg.Get("/owner-saml-config", handler.GetOwnerSAMLConfig)
	cfg.Post("/owner-saml-config", handler.SetOwnerSAMLConfig)

	cfg.Get("/owner-redis-config", handler.GetOwnerRedisConfig)
	cfg.Post("/owner-redis-config", handler.SetOwnerRedisConfig)

	cfg.Get("/owner-aws-config", handler.GetOwnerAWSConfig)
	cfg.Post("/owner-aws-config", handler.SetOwnerAWSConfig)

	cfg.Get("/owner-payment-provider-config", handler.GetOwnerPaymentProviderConfig)
	cfg.Post("/owner-payment-provider-config", handler.SetOwnerPaymentProviderConfig)

	cfg.Get("/owner-openai-config", handler.GetOwnerOpenAIConfig)
	cfg.Post("/owner-openai-config", handler.SetOwnerOpenAIConfig)

	cfg.Get("/owner-admin-user-config", handler.GetOwnerAdminUserConfig)
	cfg.Post("/owner-admin-user-config", handler.SetOwnerAdminUserConfig)

	cfg.Get("/owner-hashid-config", handler.GetOwnerHashIDConfig)
	cfg.Post("/owner-hashid-config", handler.SetOwnerHashIDConfig)

	cfg.Get("/owner-cors-config", handler.GetOwnerCORSConfig)
	cfg.Post("/owner-cors-config", handler.SetOwnerCORSConfig)

	cfg.Get("/owner-billing-config", handler.GetOwnerBillingConfig)
	cfg.Post("/owner-billing-config", handler.SetOwnerBillingConfig)

	cfg.Get("/owner-webhook-config", handler.GetOwnerWebhookConfig)
	cfg.Post("/owner-webhook-config", handler.SetOwnerWebhookConfig)

	cfg.Get("/owner-session-config", handler.GetOwnerSessionConfig)
	cfg.Post("/owner-session-config", handler.SetOwnerSessionConfig)
}
