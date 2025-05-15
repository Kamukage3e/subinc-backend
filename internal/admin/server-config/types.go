package server_config

import (
	"time"
)

// ServerConfig represents a runtime, DB-backed, hot-reloadable server-side configuration entry.
// All config is versioned, auditable, and modifiable at runtime via admin API.
type ServerConfig struct {
	Key       string    `json:"key" db:"key"`
	Value     string    `json:"value" db:"value"`
	Version   int       `json:"version" db:"version"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ServerConfigHistory tracks changes for audit/versioning.
type ServerConfigHistory struct {
	ID        int       `json:"id" db:"id"`
	Key       string    `json:"key" db:"key"`
	Value     string    `json:"value" db:"value"`
	Version   int       `json:"version" db:"version"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	UpdatedBy string    `json:"updated_by" db:"updated_by"`
}

// MigrationStatus tracks the status of a runtime or schema migration for server config
// All fields are required for real-world SaaS migration tracking
// Status: running, completed, failed
// CompletedAt and Error are nullable

type MigrationStatus struct {
	Name        string     `json:"name" db:"name"`
	Version     int        `json:"version" db:"version"`
	Status      string     `json:"status" db:"status"`
	StartedAt   time.Time  `json:"started_at" db:"started_at"`
	CompletedAt *time.Time `json:"completed_at" db:"completed_at"`
	Error       *string    `json:"error" db:"error"`
}

// OwnerDBConfig represents the owner-admin DB connection config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable DB config for owner-admin
// Key: "owner_admin_db_config"
type OwnerDBConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Name     string `json:"name"`
	SSLMode  string `json:"sslmode"`
}

// LoggingConfig represents the owner-admin logging config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable logging config for owner-admin
// Key: "owner_admin_logging_config"
type LoggingConfig struct {
	Format  string `json:"format"`
	Color   bool   `json:"color"`
	Service string `json:"service"`
	Env     string `json:"env"`
}

// RBACConfig represents the owner-admin RBAC config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable RBAC config for owner-admin
// Key: "owner_admin_rbac_config"
type RBACConfig struct {
	Enabled             bool              `json:"enabled"`
	DefaultDenyUnmapped bool              `json:"default_deny_unmapped"`
	BypassPatterns      []string          `json:"bypass_patterns"`
	RoutePermissions    []RoutePermission `json:"route_permissions"`
	LogUnauthorized     bool              `json:"log_unauthorized"`
	LogForbidden        bool              `json:"log_forbidden"`
}

// RoutePermission defines a mapping between an API route and RBAC permissions
type RoutePermission struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// JWTSecretConfig represents the owner-admin JWT secret config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable JWT secret config for owner-admin
// Key: "owner_admin_jwt_secret_config"
type JWTSecretConfig struct {
	SecretName string `json:"secret_name"`
}

// OAuthConfig represents the owner-admin OAuth config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable OAuth config for owner-admin
// Key: "owner_admin_oauth_config"
type OAuthConfig struct {
	Google struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURI  string   `json:"redirect_uri"`
		Scopes       []string `json:"scopes"`
	} `json:"google"`
}

// SAMLConfig represents the owner-admin SAML config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable SAML config for owner-admin
// Key: "owner_admin_saml_config"
type SAMLConfig struct {
	MetadataURL string `json:"metadata_url"`
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
}

// RedisConfig represents the owner-admin Redis config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable Redis config for owner-admin
// Key: "owner_admin_redis_config"
type RedisConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Password     string `json:"password"`
	DB           int    `json:"db"`
	PoolSize     int    `json:"pool_size"`
	MinIdle      int    `json:"min_idle_conns"`
	DialTimeout  string `json:"dial_timeout"`
	ReadTimeout  string `json:"read_timeout"`
	WriteTimeout string `json:"write_timeout"`
}

// AWSConfig represents the owner-admin AWS config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable AWS config for owner-admin
// Key: "owner_admin_aws_config"
type AWSConfig struct {
	Region          string `json:"region"`
	CostExplorerARN string `json:"cost_explorer_role_arn"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	AccountID       string `json:"account_id"`
}

// OwnerSMTPConfig represents the owner-admin SMTP/email config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable SMTP config for owner-admin
// Key: "owner_admin_smtp_config"
type OwnerSMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	UseTLS   bool   `json:"use_tls"`
	UseSSL   bool   `json:"use_ssl"`
}

// PaymentProviderConfig represents the owner-admin payment provider config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable payment provider config for owner-admin
// Key: "owner_admin_payment_provider_config"
type PaymentProviderConfig struct {
	StripeAPIKey        string `json:"stripe_api_key"`
	PaypalClientID      string `json:"paypal_client_id"`
	PaypalClientSecret  string `json:"paypal_client_secret"`
	GooglePayMerchantID string `json:"googlepay_merchant_id"`
	GooglePayAPIKey     string `json:"googlepay_api_key"`
	ApplePayMerchantID  string `json:"applepay_merchant_id"`
	ApplePayAPIKey      string `json:"applepay_api_key"`
	PaymentsDisabled    bool   `json:"payments_disabled"`
	// Braintree owner/global config for SaaS fallback (prod only)
	BraintreeMerchantID string `json:"braintree_merchant_id"`
	BraintreePublicKey  string `json:"braintree_public_key"`
	BraintreePrivateKey string `json:"braintree_private_key"`
	BraintreeEnv        string `json:"braintree_env"`
}

// OpenAIConfig represents the owner-admin OpenAI config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable OpenAI config for owner-admin
// Key: "owner_admin_openai_config"
type OpenAIConfig struct {
	APIKey string `json:"api_key"`
	APIURL string `json:"api_url"`
	Model  string `json:"model"`
}

// AdminUserConfig represents the owner-admin initial admin credentials, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable admin credentials for owner-admin
// Key: "owner_admin_admin_user_config"
type AdminUserConfig struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// HashIDConfig represents the owner-admin hashid salt, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable hashid salt for owner-admin
// Key: "owner_admin_hashid_config"
type HashIDConfig struct {
	Salt string `json:"salt"`
}

// CORSConfig represents the owner-admin CORS config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable CORS config for owner-admin
// Key: "owner_admin_cors_config"
type CORSConfig struct {
	Origins          string `json:"origins"`
	Methods          string `json:"methods"`
	Headers          string `json:"headers"`
	AllowCredentials bool   `json:"allow_credentials"`
}

// BillingConfig represents the owner-admin billing config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable billing config for owner-admin
// Key: "owner_admin_billing_config"
type BillingConfig struct {
	TaxRate    float64 `json:"tax_rate"`
	FixedFee   float64 `json:"fixed_fee"`
	PercentFee float64 `json:"percent_fee"`
}

// WebhookConfig represents the owner-admin webhook config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable webhook config for owner-admin
// Key: "owner_admin_webhook_config"
type WebhookConfig struct {
	EventsURL string `json:"events_url"`
}

// SessionConfig represents the owner-admin session config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable session config for owner-admin
// Key: "owner_admin_session_config"
type SessionConfig struct {
	Prefix string `json:"prefix"`
	TTL    string `json:"ttl"`
}

// ClientDBConfig represents the client-admin DB config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable DB config for client-admin
// Key: "client_admin_db_config_{tenantID}"
type ClientDBConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSLMode  string `json:"ssl_mode"`
	Schema   string `json:"schema"`
}

// ClientRedisConfig represents the client-admin Redis config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable Redis config for client-admin
// Key: "client_admin_redis_config_{tenantID}"
type ClientRedisConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Password     string `json:"password"`
	DB           int    `json:"db"`
	PoolSize     int    `json:"pool_size"`
	MinIdle      int    `json:"min_idle_conns"`
	DialTimeout  string `json:"dial_timeout"`
	ReadTimeout  string `json:"read_timeout"`
	WriteTimeout string `json:"write_timeout"`
}

// ClientAWSConfig represents the client-admin AWS config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable AWS config for client-admin
// Key: "client_admin_aws_config_{tenantID}"
type ClientAWSConfig struct {
	Region          string `json:"region"`
	CostExplorerARN string `json:"cost_explorer_role_arn"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	AccountID       string `json:"account_id"`
}

// ClientSMTPConfig represents the client-admin SMTP config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable SMTP config for client-admin
// Key: "client_admin_smtp_config_{tenantID}"
type ClientSMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	UseTLS   bool   `json:"use_tls"`
	UseSSL   bool   `json:"use_ssl"`
}

// ClientPaymentProviderConfig represents the client-admin payment provider config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable payment provider config for client-admin
// Key: "client_admin_payment_provider_config_{tenantID}"
type ClientPaymentProviderConfig struct {
	StripeAPIKey        string `json:"stripe_api_key"`
	PaypalClientID      string `json:"paypal_client_id"`
	PaypalClientSecret  string `json:"paypal_client_secret"`
	GooglePayMerchantID string `json:"googlepay_merchant_id"`
	GooglePayAPIKey     string `json:"googlepay_api_key"`
	ApplePayMerchantID  string `json:"applepay_merchant_id"`
	ApplePayAPIKey      string `json:"applepay_api_key"`
	PaymentsDisabled    bool   `json:"payments_disabled"`
	BraintreeMerchantID string `json:"braintree_merchant_id"`
	BraintreePublicKey  string `json:"braintree_public_key"`
	BraintreePrivateKey string `json:"braintree_private_key"`
	BraintreeEnv        string `json:"braintree_env"`
}

// ClientJWTSecretConfig represents the client-admin JWT secret config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable JWT secret config for client-admin
// Key: "client_admin_jwt_secret_config_{tenantID}"
type ClientJWTSecretConfig struct {
	SecretName string `json:"secret_name"`
}

// ClientOAuthConfig represents the client-admin OAuth config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable OAuth config for client-admin
// Key: "client_admin_oauth_config_{tenantID}"
type ClientOAuthConfig struct {
	Google struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURI  string   `json:"redirect_uri"`
		Scopes       []string `json:"scopes"`
	} `json:"google"`
}

// ClientSAMLConfig represents the client-admin SAML config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable SAML config for client-admin
// Key: "client_admin_saml_config_{tenantID}"
type ClientSAMLConfig struct {
	MetadataURL string `json:"metadata_url"`
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
}

// ClientOpenAIConfig represents the client-admin OpenAI config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable OpenAI config for client-admin
// Key: "client_admin_openai_config_{tenantID}"
type ClientOpenAIConfig struct {
	APIKey string `json:"api_key"`
	APIURL string `json:"api_url"`
}

// ClientWebhookConfig represents the client-admin webhook config for a tenant, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable webhook config for client-admin
// Key: "client_admin_webhook_config_{tenantID}"
type ClientWebhookConfig struct {
	EventsURL string `json:"events_url"`
}

// GraphQLConfig represents the owner-admin GraphQL config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable GraphQL enable/disable for owner-admin
// Key: "owner_admin_graphql_config"
type GraphQLConfig struct {
	Enabled bool `json:"enabled"`
}
