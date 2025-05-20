package server_config

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	rbacmiddleware "github.com/subinc/subinc-backend/internal/pkg/rbacmiddleware"
)

// RegisterAdminServerConfigRoutes registers admin API routes for server config management.
func RegisterAdminServerConfigRoutes(router fiber.Router, handler *Handler, jwtSecret string) {
	cfg := router.Group(
		"/server-config",
		security_management.OIDCMiddleware(jwtSecret),
	)
	cfg.Get("/list", rbacmiddleware.RBACMiddleware("server-config", "read", nil), handler.ListConfig)
	cfg.Get("/get/:key", rbacmiddleware.RBACMiddleware("server-config", "read", nil), handler.GetConfig)
	cfg.Post("/set", rbacmiddleware.RBACMiddleware("server-config", "update", nil), handler.SetConfig)
	cfg.Get("/history/:key", rbacmiddleware.RBACMiddleware("server-config", "read", nil), handler.ConfigHistory)

	// Add missing real handlers for migration status and config
	cfg.Get("/migration-status", rbacmiddleware.RBACMiddleware("migration-status", "read", nil), handler.ListMigrationStatus)
	cfg.Get("/migration-status/:name", rbacmiddleware.RBACMiddleware("migration-status", "read", nil), handler.GetMigrationStatus)
	cfg.Post("/migration-status", rbacmiddleware.RBACMiddleware("migration-status", "update", nil), handler.SetMigrationStatus)

	cfg.Get("/owner-db-config", rbacmiddleware.RBACMiddleware("owner-db-config", "read", nil), handler.GetOwnerDBConfig)
	cfg.Post("/owner-db-config", rbacmiddleware.RBACMiddleware("owner-db-config", "update", nil), handler.SetOwnerDBConfig)

	cfg.Get("/owner-logging-config", rbacmiddleware.RBACMiddleware("owner-logging-config", "read", nil), handler.GetOwnerLoggingConfig)
	cfg.Post("/owner-logging-config", rbacmiddleware.RBACMiddleware("owner-logging-config", "update", nil), handler.SetOwnerLoggingConfig)

	cfg.Get("/owner-jwt-secret-config", rbacmiddleware.RBACMiddleware("owner-jwt-secret-config", "read", nil), handler.GetOwnerJWTSecretConfig)
	cfg.Post("/owner-jwt-secret-config", rbacmiddleware.RBACMiddleware("owner-jwt-secret-config", "update", nil), handler.SetOwnerJWTSecretConfig)

	cfg.Get("/owner-oauth-config", rbacmiddleware.RBACMiddleware("owner-oauth-config", "read", nil), handler.GetOwnerOAuthConfig)
	cfg.Post("/owner-oauth-config", rbacmiddleware.RBACMiddleware("owner-oauth-config", "update", nil), handler.SetOwnerOAuthConfig)
	cfg.Get("/owner-saml-config", rbacmiddleware.RBACMiddleware("owner-saml-config", "read", nil), handler.GetOwnerSAMLConfig)
	cfg.Post("/owner-saml-config", rbacmiddleware.RBACMiddleware("owner-saml-config", "update", nil), handler.SetOwnerSAMLConfig)

	cfg.Get("/owner-redis-config", rbacmiddleware.RBACMiddleware("owner-redis-config", "read", nil), handler.GetOwnerRedisConfig)
	cfg.Post("/owner-redis-config", rbacmiddleware.RBACMiddleware("owner-redis-config", "update", nil), handler.SetOwnerRedisConfig)

	cfg.Get("/owner-aws-config", rbacmiddleware.RBACMiddleware("owner-aws-config", "read", nil), handler.GetOwnerAWSConfig)
	cfg.Post("/owner-aws-config", rbacmiddleware.RBACMiddleware("owner-aws-config", "update", nil), handler.SetOwnerAWSConfig)

	cfg.Get("/owner-payment-provider-config", rbacmiddleware.RBACMiddleware("owner-payment-provider-config", "read", nil), handler.GetOwnerPaymentProviderConfig)
	cfg.Post("/owner-payment-provider-config", rbacmiddleware.RBACMiddleware("owner-payment-provider-config", "update", nil), handler.SetOwnerPaymentProviderConfig)

	cfg.Get("/owner-smtp-config", rbacmiddleware.RBACMiddleware("owner-smtp-config", "read", nil), handler.GetOwnerSMTPConfig)
	cfg.Post("/owner-smtp-config", rbacmiddleware.RBACMiddleware("owner-smtp-config", "update", nil), handler.SetOwnerSMTPConfig)

	cfg.Get("/owner-openai-config", rbacmiddleware.RBACMiddleware("owner-openai-config", "read", nil), handler.GetOwnerOpenAIConfig)
	cfg.Post("/owner-openai-config", rbacmiddleware.RBACMiddleware("owner-openai-config", "update", nil), handler.SetOwnerOpenAIConfig)

	cfg.Get("/owner-admin-user-config", rbacmiddleware.RBACMiddleware("owner-admin-user-config", "read", nil), handler.GetOwnerAdminUserConfig)
	cfg.Post("/owner-admin-user-config", rbacmiddleware.RBACMiddleware("owner-admin-user-config", "update", nil), handler.SetOwnerAdminUserConfig)

	cfg.Get("/owner-hashid-config", rbacmiddleware.RBACMiddleware("owner-hashid-config", "read", nil), handler.GetOwnerHashIDConfig)
	cfg.Post("/owner-hashid-config", rbacmiddleware.RBACMiddleware("owner-hashid-config", "update", nil), handler.SetOwnerHashIDConfig)

	cfg.Get("/owner-cors-config", rbacmiddleware.RBACMiddleware("owner-cors-config", "read", nil), handler.GetOwnerCORSConfig)
	cfg.Post("/owner-cors-config", rbacmiddleware.RBACMiddleware("owner-cors-config", "update", nil), handler.SetOwnerCORSConfig)

	cfg.Get("/owner-billing-config", rbacmiddleware.RBACMiddleware("owner-billing-config", "read", nil), handler.GetOwnerBillingConfig)
	cfg.Post("/owner-billing-config", rbacmiddleware.RBACMiddleware("owner-billing-config", "update", nil), handler.SetOwnerBillingConfig)

	cfg.Get("/owner-webhook-config", rbacmiddleware.RBACMiddleware("owner-webhook-config", "read", nil), handler.GetOwnerWebhookConfig)
	cfg.Post("/owner-webhook-config", rbacmiddleware.RBACMiddleware("owner-webhook-config", "update", nil), handler.SetOwnerWebhookConfig)

	cfg.Get("/owner-session-config", rbacmiddleware.RBACMiddleware("owner-session-config", "read", nil), handler.GetOwnerSessionConfig)
	cfg.Post("/owner-session-config", rbacmiddleware.RBACMiddleware("owner-session-config", "update", nil), handler.SetOwnerSessionConfig)

	cfg.Get("/owner-rbac-config", rbacmiddleware.RBACMiddleware("owner-rbac-config", "read", nil), handler.GetOwnerRBACConfig)
	cfg.Post("/owner-rbac-config", rbacmiddleware.RBACMiddleware("owner-rbac-config", "update", nil), handler.SetOwnerRBACConfig)

	cfg.Get("/owner-graphql-config", rbacmiddleware.RBACMiddleware("owner-graphql-config", "read", nil), handler.GetOwnerGraphQLConfig)
	cfg.Post("/owner-graphql-config", rbacmiddleware.RBACMiddleware("owner-graphql-config", "update", nil), handler.SetOwnerGraphQLConfig)

	// Client-admin DB config endpoints
	cfg.Get("/client-config/db/:tenantID", rbacmiddleware.RBACMiddleware("client-db-config", "read", nil), handler.GetClientDBConfig)
	cfg.Post("/client-config/db/:tenantID", rbacmiddleware.RBACMiddleware("client-db-config", "update", nil), handler.SetClientDBConfig)
	// Client-admin Redis config endpoints
	cfg.Get("/client-config/redis/:tenantID", rbacmiddleware.RBACMiddleware("client-redis-config", "read", nil), handler.GetClientRedisConfig)
	cfg.Post("/client-config/redis/:tenantID", rbacmiddleware.RBACMiddleware("client-redis-config", "update", nil), handler.SetClientRedisConfig)
	// Client-admin AWS config endpoints
	cfg.Get("/client-config/aws/:tenantID", rbacmiddleware.RBACMiddleware("client-aws-config", "read", nil), handler.GetClientAWSConfig)
	cfg.Post("/client-config/aws/:tenantID", rbacmiddleware.RBACMiddleware("client-aws-config", "update", nil), handler.SetClientAWSConfig)
	// Client-admin SMTP config endpoints
	cfg.Get("/client-config/smtp/:tenantID", rbacmiddleware.RBACMiddleware("client-smtp-config", "read", nil), handler.GetClientSMTPConfig)
	cfg.Post("/client-config/smtp/:tenantID", rbacmiddleware.RBACMiddleware("client-smtp-config", "update", nil), handler.SetClientSMTPConfig)

	// Client-admin payment provider config endpoints
	cfg.Get("/client-config/payment-provider/:tenantID", rbacmiddleware.RBACMiddleware("client-payment-provider-config", "read", nil), handler.GetClientPaymentProviderConfig)
	cfg.Post("/client-config/payment-provider/:tenantID", rbacmiddleware.RBACMiddleware("client-payment-provider-config", "update", nil), handler.SetClientPaymentProviderConfig)

	// Client-admin JWT secret config endpoints
	cfg.Get("/client-config/jwt-secret/:tenantID", rbacmiddleware.RBACMiddleware("client-jwt-secret-config", "read", nil), handler.GetClientJWTSecretConfig)
	cfg.Post("/client-config/jwt-secret/:tenantID", rbacmiddleware.RBACMiddleware("client-jwt-secret-config", "update", nil), handler.SetClientJWTSecretConfig)

	// Client-admin OAuth config endpoints
	cfg.Get("/client-config/oauth/:tenantID", rbacmiddleware.RBACMiddleware("client-oauth-config", "read", nil), handler.GetClientOAuthConfig)
	cfg.Post("/client-config/oauth/:tenantID", rbacmiddleware.RBACMiddleware("client-oauth-config", "update", nil), handler.SetClientOAuthConfig)

	// Client-admin SAML config endpoints
	cfg.Get("/client-config/saml/:tenantID", rbacmiddleware.RBACMiddleware("client-saml-config", "read", nil), handler.GetClientSAMLConfig)
	cfg.Post("/client-config/saml/:tenantID", rbacmiddleware.RBACMiddleware("client-saml-config", "update", nil), handler.SetClientSAMLConfig)

	// Client-admin OpenAI config endpoints
	cfg.Get("/client-config/openai/:tenantID", rbacmiddleware.RBACMiddleware("client-openai-config", "read", nil), handler.GetClientOpenAIConfig)
	cfg.Post("/client-config/openai/:tenantID", rbacmiddleware.RBACMiddleware("client-openai-config", "update", nil), handler.SetClientOpenAIConfig)

	// Client-admin Webhook config endpoints
	cfg.Get("/client-config/webhook/:tenantID", rbacmiddleware.RBACMiddleware("client-webhook-config", "read", nil), handler.GetClientWebhookConfig)
	cfg.Post("/client-config/webhook/:tenantID", rbacmiddleware.RBACMiddleware("client-webhook-config", "update", nil), handler.SetClientWebhookConfig)
}
