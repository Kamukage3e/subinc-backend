package server_config

import (
	"context"
	"encoding/json"
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
