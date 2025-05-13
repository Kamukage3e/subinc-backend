package server_config

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// Service provides runtime CRUD, in-memory cache, and hot-reload for server config.
type Service struct {
	store       *Store
	cache       map[string]ServerConfig
	mu          sync.RWMutex
	refresh     time.Duration
	stopCh      chan struct{}
	AuditLogger security_management.AuditLogger
	RBACService rbac_management.RBACService
}

func NewService(store *Store, refresh time.Duration, auditLogger security_management.AuditLogger, rbac rbac_management.RBACService) *Service {
	s := &Service{
		store:       store,
		cache:       make(map[string]ServerConfig),
		refresh:     refresh,
		stopCh:      make(chan struct{}),
		AuditLogger: auditLogger,
		RBACService: rbac,
	}
	s.reload(context.Background())
	go s.autoReload()
	return s
}

func (s *Service) Get(ctx context.Context, key string) (ServerConfig, error) {
	s.mu.RLock()
	cfg, ok := s.cache[key]
	s.mu.RUnlock()
	if ok {
		return cfg, nil
	}
	cfg, err := s.store.Get(ctx, key)
	if err != nil {
		return ServerConfig{}, err
	}
	s.mu.Lock()
	s.cache[key] = cfg
	s.mu.Unlock()
	return cfg, nil
}

func (s *Service) Set(ctx context.Context, key, value, updatedBy string) (ServerConfig, error) {
	cfg, err := s.store.Set(ctx, key, value, updatedBy)
	if err != nil {
		return ServerConfig{}, err
	}
	s.mu.Lock()
	s.cache[key] = cfg
	s.mu.Unlock()
	return cfg, nil
}

func (s *Service) List(ctx context.Context) ([]ServerConfig, error) {
	return s.store.List(ctx)
}

func (s *Service) History(ctx context.Context, key string) ([]ServerConfigHistory, error) {
	return s.store.History(ctx, key)
}

func (s *Service) reload(ctx context.Context) {
	cfgs, err := s.store.List(ctx)
	if err != nil {
		return
	}
	s.mu.Lock()
	for _, cfg := range cfgs {
		s.cache[cfg.Key] = cfg
	}
	s.mu.Unlock()
}

func (s *Service) autoReload() {
	ticker := time.NewTicker(s.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reload(context.Background())
		case <-s.stopCh:
			return
		}
	}
}

func (s *Service) Stop() {
	close(s.stopCh)
}

func (s *Service) ListMigrationStatus(ctx context.Context) ([]MigrationStatus, error) {
	return s.store.ListMigrationStatus(ctx)
}

func (s *Service) GetMigrationStatus(ctx context.Context, name string) (*MigrationStatus, error) {
	return s.store.GetMigrationStatus(ctx, name)
}

func (s *Service) SetMigrationStatus(ctx context.Context, status *MigrationStatus) (*MigrationStatus, error) {
	return s.store.SetMigrationStatus(ctx, status)
}

// GetOwnerDBConfig returns the current owner-admin DB config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerDBConfig(ctx context.Context) (OwnerDBConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_db_config")
	if err != nil {
		return OwnerDBConfig{}, err
	}
	if cfg.Value == "" {
		return OwnerDBConfig{}, nil
	}
	var dbCfg OwnerDBConfig
	if err := json.Unmarshal([]byte(cfg.Value), &dbCfg); err != nil {
		return OwnerDBConfig{}, err
	}
	return dbCfg, nil
}

// SetOwnerDBConfig sets the owner-admin DB config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerDBConfig(ctx context.Context, dbCfg OwnerDBConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(dbCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_db_config", string(b), updatedBy)
}

// GetOwnerLoggingConfig returns the current owner-admin logging config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerLoggingConfig(ctx context.Context) (LoggingConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_logging_config")
	if err != nil {
		return LoggingConfig{}, err
	}
	if cfg.Value == "" {
		return LoggingConfig{}, nil
	}
	var logCfg LoggingConfig
	if err := json.Unmarshal([]byte(cfg.Value), &logCfg); err != nil {
		return LoggingConfig{}, err
	}
	return logCfg, nil
}

// SetOwnerLoggingConfig sets the owner-admin logging config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerLoggingConfig(ctx context.Context, logCfg LoggingConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(logCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_logging_config", string(b), updatedBy)
}

// GetOwnerJWTSecretConfig returns the current owner-admin JWT secret config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerJWTSecretConfig(ctx context.Context) (JWTSecretConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_jwt_secret_config")
	if err != nil {
		return JWTSecretConfig{}, err
	}
	if cfg.Value == "" {
		return JWTSecretConfig{}, nil
	}
	var jwtCfg JWTSecretConfig
	if err := json.Unmarshal([]byte(cfg.Value), &jwtCfg); err != nil {
		return JWTSecretConfig{}, err
	}
	return jwtCfg, nil
}

// SetOwnerJWTSecretConfig sets the owner-admin JWT secret config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerJWTSecretConfig(ctx context.Context, jwtCfg JWTSecretConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(jwtCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_jwt_secret_config", string(b), updatedBy)
}

// GetOwnerOAuthConfig returns the current owner-admin OAuth config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerOAuthConfig(ctx context.Context) (OAuthConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_oauth_config")
	if err != nil {
		return OAuthConfig{}, err
	}
	if cfg.Value == "" {
		return OAuthConfig{}, nil
	}
	var oauthCfg OAuthConfig
	if err := json.Unmarshal([]byte(cfg.Value), &oauthCfg); err != nil {
		return OAuthConfig{}, err
	}
	return oauthCfg, nil
}

// SetOwnerOAuthConfig sets the owner-admin OAuth config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerOAuthConfig(ctx context.Context, oauthCfg OAuthConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(oauthCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_oauth_config", string(b), updatedBy)
}

// GetOwnerSAMLConfig returns the current owner-admin SAML config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerSAMLConfig(ctx context.Context) (SAMLConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_saml_config")
	if err != nil {
		return SAMLConfig{}, err
	}
	if cfg.Value == "" {
		return SAMLConfig{}, nil
	}
	var samlCfg SAMLConfig
	if err := json.Unmarshal([]byte(cfg.Value), &samlCfg); err != nil {
		return SAMLConfig{}, err
	}
	return samlCfg, nil
}

// SetOwnerSAMLConfig sets the owner-admin SAML config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerSAMLConfig(ctx context.Context, samlCfg SAMLConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(samlCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_saml_config", string(b), updatedBy)
}

// GetOwnerRedisConfig returns the current owner-admin Redis config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerRedisConfig(ctx context.Context) (RedisConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_redis_config")
	if err != nil {
		return RedisConfig{}, err
	}
	if cfg.Value == "" {
		return RedisConfig{}, nil
	}
	var redisCfg RedisConfig
	if err := json.Unmarshal([]byte(cfg.Value), &redisCfg); err != nil {
		return RedisConfig{}, err
	}
	return redisCfg, nil
}

// SetOwnerRedisConfig sets the owner-admin Redis config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerRedisConfig(ctx context.Context, redisCfg RedisConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(redisCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_redis_config", string(b), updatedBy)
}

// GetOwnerAWSConfig returns the current owner-admin AWS config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerAWSConfig(ctx context.Context) (AWSConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_aws_config")
	if err != nil {
		return AWSConfig{}, err
	}
	if cfg.Value == "" {
		return AWSConfig{}, nil
	}
	var awsCfg AWSConfig
	if err := json.Unmarshal([]byte(cfg.Value), &awsCfg); err != nil {
		return AWSConfig{}, err
	}
	return awsCfg, nil
}

// SetOwnerAWSConfig sets the owner-admin AWS config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerAWSConfig(ctx context.Context, awsCfg AWSConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(awsCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_aws_config", string(b), updatedBy)
}

// GetOwnerPaymentProviderConfig returns the current owner-admin payment provider config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerPaymentProviderConfig(ctx context.Context) (PaymentProviderConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_payment_provider_config")
	if err != nil {
		return PaymentProviderConfig{}, err
	}
	if cfg.Value == "" {
		return PaymentProviderConfig{}, nil
	}
	var payCfg PaymentProviderConfig
	if err := json.Unmarshal([]byte(cfg.Value), &payCfg); err != nil {
		return PaymentProviderConfig{}, err
	}
	return payCfg, nil
}

// SetOwnerPaymentProviderConfig sets the owner-admin payment provider config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerPaymentProviderConfig(ctx context.Context, payCfg PaymentProviderConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(payCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_payment_provider_config", string(b), updatedBy)
}

// GetOwnerOpenAIConfig returns the current owner-admin OpenAI config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerOpenAIConfig(ctx context.Context) (OpenAIConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_openai_config")
	if err != nil {
		return OpenAIConfig{}, err
	}
	if cfg.Value == "" {
		return OpenAIConfig{}, nil
	}
	var openaiCfg OpenAIConfig
	if err := json.Unmarshal([]byte(cfg.Value), &openaiCfg); err != nil {
		return OpenAIConfig{}, err
	}
	return openaiCfg, nil
}

// SetOwnerOpenAIConfig sets the owner-admin OpenAI config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerOpenAIConfig(ctx context.Context, openaiCfg OpenAIConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(openaiCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_openai_config", string(b), updatedBy)
}

// GetOwnerAdminUserConfig returns the current owner-admin initial admin credentials from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerAdminUserConfig(ctx context.Context) (AdminUserConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_admin_user_config")
	if err != nil {
		return AdminUserConfig{}, err
	}
	if cfg.Value == "" {
		return AdminUserConfig{}, nil
	}
	var adminCfg AdminUserConfig
	if err := json.Unmarshal([]byte(cfg.Value), &adminCfg); err != nil {
		return AdminUserConfig{}, err
	}
	return adminCfg, nil
}

// SetOwnerAdminUserConfig sets the owner-admin initial admin credentials in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerAdminUserConfig(ctx context.Context, adminCfg AdminUserConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(adminCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_admin_user_config", string(b), updatedBy)
}

// GetOwnerHashIDConfig returns the current owner-admin hashid salt from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerHashIDConfig(ctx context.Context) (HashIDConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_hashid_config")
	if err != nil {
		return HashIDConfig{}, err
	}
	if cfg.Value == "" {
		return HashIDConfig{}, nil
	}
	var hashidCfg HashIDConfig
	if err := json.Unmarshal([]byte(cfg.Value), &hashidCfg); err != nil {
		return HashIDConfig{}, err
	}
	return hashidCfg, nil
}

// SetOwnerHashIDConfig sets the owner-admin hashid salt in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerHashIDConfig(ctx context.Context, hashidCfg HashIDConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(hashidCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_hashid_config", string(b), updatedBy)
}

// GetOwnerCORSConfig returns the current owner-admin CORS config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerCORSConfig(ctx context.Context) (CORSConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_cors_config")
	if err != nil {
		return CORSConfig{}, err
	}
	if cfg.Value == "" {
		return CORSConfig{}, nil
	}
	var corsCfg CORSConfig
	if err := json.Unmarshal([]byte(cfg.Value), &corsCfg); err != nil {
		return CORSConfig{}, err
	}
	return corsCfg, nil
}

// SetOwnerCORSConfig sets the owner-admin CORS config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerCORSConfig(ctx context.Context, corsCfg CORSConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(corsCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_cors_config", string(b), updatedBy)
}

// GetOwnerBillingConfig returns the current owner-admin billing config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerBillingConfig(ctx context.Context) (BillingConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_billing_config")
	if err != nil {
		return BillingConfig{}, err
	}
	if cfg.Value == "" {
		return BillingConfig{}, nil
	}
	var billingCfg BillingConfig
	if err := json.Unmarshal([]byte(cfg.Value), &billingCfg); err != nil {
		return BillingConfig{}, err
	}
	return billingCfg, nil
}

// SetOwnerBillingConfig sets the owner-admin billing config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerBillingConfig(ctx context.Context, billingCfg BillingConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(billingCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_billing_config", string(b), updatedBy)
}

// GetOwnerWebhookConfig returns the current owner-admin webhook config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerWebhookConfig(ctx context.Context) (WebhookConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_webhook_config")
	if err != nil {
		return WebhookConfig{}, err
	}
	if cfg.Value == "" {
		return WebhookConfig{}, nil
	}
	var webhookCfg WebhookConfig
	if err := json.Unmarshal([]byte(cfg.Value), &webhookCfg); err != nil {
		return WebhookConfig{}, err
	}
	return webhookCfg, nil
}

// SetOwnerWebhookConfig sets the owner-admin webhook config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerWebhookConfig(ctx context.Context, webhookCfg WebhookConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(webhookCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_webhook_config", string(b), updatedBy)
}

// GetOwnerSessionConfig returns the current owner-admin session config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerSessionConfig(ctx context.Context) (SessionConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_session_config")
	if err != nil {
		return SessionConfig{}, err
	}
	if cfg.Value == "" {
		return SessionConfig{}, nil
	}
	var sessionCfg SessionConfig
	if err := json.Unmarshal([]byte(cfg.Value), &sessionCfg); err != nil {
		return SessionConfig{}, err
	}
	return sessionCfg, nil
}

// SetOwnerSessionConfig sets the owner-admin session config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerSessionConfig(ctx context.Context, sessionCfg SessionConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(sessionCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_session_config", string(b), updatedBy)
}

// GetClientDBConfig returns the current client-admin DB config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientDBConfig(ctx context.Context, tenantID string) (ClientDBConfig, error) {
	if tenantID == "" {
		return ClientDBConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_db_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientDBConfig{}, err
	}
	if cfg.Value == "" {
		return ClientDBConfig{}, nil
	}
	var dbCfg ClientDBConfig
	if err := json.Unmarshal([]byte(cfg.Value), &dbCfg); err != nil {
		return ClientDBConfig{}, err
	}
	return dbCfg, nil
}

// SetClientDBConfig sets the client-admin DB config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientDBConfig(ctx context.Context, tenantID string, dbCfg ClientDBConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_db_config_" + tenantID
	b, err := json.Marshal(dbCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientRedisConfig returns the current client-admin Redis config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientRedisConfig(ctx context.Context, tenantID string) (ClientRedisConfig, error) {
	if tenantID == "" {
		return ClientRedisConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_redis_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientRedisConfig{}, err
	}
	if cfg.Value == "" {
		return ClientRedisConfig{}, nil
	}
	var redisCfg ClientRedisConfig
	if err := json.Unmarshal([]byte(cfg.Value), &redisCfg); err != nil {
		return ClientRedisConfig{}, err
	}
	return redisCfg, nil
}

// SetClientRedisConfig sets the client-admin Redis config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientRedisConfig(ctx context.Context, tenantID string, redisCfg ClientRedisConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_redis_config_" + tenantID
	b, err := json.Marshal(redisCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientAWSConfig returns the current client-admin AWS config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientAWSConfig(ctx context.Context, tenantID string) (ClientAWSConfig, error) {
	if tenantID == "" {
		return ClientAWSConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_aws_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientAWSConfig{}, err
	}
	if cfg.Value == "" {
		return ClientAWSConfig{}, nil
	}
	var awsCfg ClientAWSConfig
	if err := json.Unmarshal([]byte(cfg.Value), &awsCfg); err != nil {
		return ClientAWSConfig{}, err
	}
	return awsCfg, nil
}

// SetClientAWSConfig sets the client-admin AWS config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientAWSConfig(ctx context.Context, tenantID string, awsCfg ClientAWSConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_aws_config_" + tenantID
	b, err := json.Marshal(awsCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientSMTPConfig returns the current client-admin SMTP config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientSMTPConfig(ctx context.Context, tenantID string) (ClientSMTPConfig, error) {
	if tenantID == "" {
		return ClientSMTPConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_smtp_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientSMTPConfig{}, err
	}
	if cfg.Value == "" {
		return ClientSMTPConfig{}, nil
	}
	var smtpCfg ClientSMTPConfig
	if err := json.Unmarshal([]byte(cfg.Value), &smtpCfg); err != nil {
		return ClientSMTPConfig{}, err
	}
	return smtpCfg, nil
}

// SetClientSMTPConfig sets the client-admin SMTP config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientSMTPConfig(ctx context.Context, tenantID string, smtpCfg ClientSMTPConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_smtp_config_" + tenantID
	b, err := json.Marshal(smtpCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetOwnerSMTPConfig returns the current owner-admin SMTP config from server_config (runtime, hot-reloadable)
func (s *Service) GetOwnerSMTPConfig(ctx context.Context) (OwnerSMTPConfig, error) {
	cfg, err := s.Get(ctx, "owner_admin_smtp_config")
	if err != nil {
		return OwnerSMTPConfig{}, err
	}
	if cfg.Value == "" {
		return OwnerSMTPConfig{}, nil
	}
	var smtpCfg OwnerSMTPConfig
	if err := json.Unmarshal([]byte(cfg.Value), &smtpCfg); err != nil {
		return OwnerSMTPConfig{}, err
	}
	return smtpCfg, nil
}

// SetOwnerSMTPConfig sets the owner-admin SMTP config in server_config (runtime, hot-reloadable)
func (s *Service) SetOwnerSMTPConfig(ctx context.Context, smtpCfg OwnerSMTPConfig, updatedBy string) (ServerConfig, error) {
	b, err := json.Marshal(smtpCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, "owner_admin_smtp_config", string(b), updatedBy)
}

// GetClientPaymentProviderConfig returns the current client-admin payment provider config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientPaymentProviderConfig(ctx context.Context, tenantID string) (ClientPaymentProviderConfig, error) {
	if tenantID == "" {
		return ClientPaymentProviderConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_payment_provider_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientPaymentProviderConfig{}, err
	}
	if cfg.Value == "" {
		return ClientPaymentProviderConfig{}, nil
	}
	var paymentCfg ClientPaymentProviderConfig
	if err := json.Unmarshal([]byte(cfg.Value), &paymentCfg); err != nil {
		return ClientPaymentProviderConfig{}, err
	}
	return paymentCfg, nil
}

// SetClientPaymentProviderConfig sets the client-admin payment provider config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientPaymentProviderConfig(ctx context.Context, tenantID string, paymentCfg ClientPaymentProviderConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_payment_provider_config_" + tenantID
	b, err := json.Marshal(paymentCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientJWTSecretConfig returns the current client-admin JWT secret config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientJWTSecretConfig(ctx context.Context, tenantID string) (ClientJWTSecretConfig, error) {
	if tenantID == "" {
		return ClientJWTSecretConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_jwt_secret_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientJWTSecretConfig{}, err
	}
	if cfg.Value == "" {
		return ClientJWTSecretConfig{}, nil
	}
	var jwtCfg ClientJWTSecretConfig
	if err := json.Unmarshal([]byte(cfg.Value), &jwtCfg); err != nil {
		return ClientJWTSecretConfig{}, err
	}
	return jwtCfg, nil
}

// SetClientJWTSecretConfig sets the client-admin JWT secret config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientJWTSecretConfig(ctx context.Context, tenantID string, jwtCfg ClientJWTSecretConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_jwt_secret_config_" + tenantID
	b, err := json.Marshal(jwtCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientOAuthConfig returns the current client-admin OAuth config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientOAuthConfig(ctx context.Context, tenantID string) (ClientOAuthConfig, error) {
	if tenantID == "" {
		return ClientOAuthConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_oauth_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientOAuthConfig{}, err
	}
	if cfg.Value == "" {
		return ClientOAuthConfig{}, nil
	}
	var oauthCfg ClientOAuthConfig
	if err := json.Unmarshal([]byte(cfg.Value), &oauthCfg); err != nil {
		return ClientOAuthConfig{}, err
	}
	return oauthCfg, nil
}

// SetClientOAuthConfig sets the client-admin OAuth config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientOAuthConfig(ctx context.Context, tenantID string, oauthCfg ClientOAuthConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_oauth_config_" + tenantID
	b, err := json.Marshal(oauthCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientSAMLConfig returns the current client-admin SAML config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientSAMLConfig(ctx context.Context, tenantID string) (ClientSAMLConfig, error) {
	if tenantID == "" {
		return ClientSAMLConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_saml_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientSAMLConfig{}, err
	}
	if cfg.Value == "" {
		return ClientSAMLConfig{}, nil
	}
	var samlCfg ClientSAMLConfig
	if err := json.Unmarshal([]byte(cfg.Value), &samlCfg); err != nil {
		return ClientSAMLConfig{}, err
	}
	return samlCfg, nil
}

// SetClientSAMLConfig sets the client-admin SAML config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientSAMLConfig(ctx context.Context, tenantID string, samlCfg ClientSAMLConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_saml_config_" + tenantID
	b, err := json.Marshal(samlCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientOpenAIConfig returns the current client-admin OpenAI config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientOpenAIConfig(ctx context.Context, tenantID string) (ClientOpenAIConfig, error) {
	if tenantID == "" {
		return ClientOpenAIConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_openai_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientOpenAIConfig{}, err
	}
	if cfg.Value == "" {
		return ClientOpenAIConfig{}, nil
	}
	var openaiCfg ClientOpenAIConfig
	if err := json.Unmarshal([]byte(cfg.Value), &openaiCfg); err != nil {
		return ClientOpenAIConfig{}, err
	}
	return openaiCfg, nil
}

// SetClientOpenAIConfig sets the client-admin OpenAI config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientOpenAIConfig(ctx context.Context, tenantID string, openaiCfg ClientOpenAIConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_openai_config_" + tenantID
	b, err := json.Marshal(openaiCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}

// GetClientWebhookConfig returns the current client-admin webhook config for a tenant from server_config (runtime, hot-reloadable)
func (s *Service) GetClientWebhookConfig(ctx context.Context, tenantID string) (ClientWebhookConfig, error) {
	if tenantID == "" {
		return ClientWebhookConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_webhook_config_" + tenantID
	cfg, err := s.Get(ctx, key)
	if err != nil {
		return ClientWebhookConfig{}, err
	}
	if cfg.Value == "" {
		return ClientWebhookConfig{}, nil
	}
	var webhookCfg ClientWebhookConfig
	if err := json.Unmarshal([]byte(cfg.Value), &webhookCfg); err != nil {
		return ClientWebhookConfig{}, err
	}
	return webhookCfg, nil
}

// SetClientWebhookConfig sets the client-admin webhook config for a tenant in server_config (runtime, hot-reloadable)
func (s *Service) SetClientWebhookConfig(ctx context.Context, tenantID string, webhookCfg ClientWebhookConfig, updatedBy string) (ServerConfig, error) {
	if tenantID == "" {
		return ServerConfig{}, errors.New("tenantID required")
	}
	key := "client_admin_webhook_config_" + tenantID
	b, err := json.Marshal(webhookCfg)
	if err != nil {
		return ServerConfig{}, err
	}
	return s.Set(ctx, key, string(b), updatedBy)
}
