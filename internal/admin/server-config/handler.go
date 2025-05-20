package server_config

import (
	"context"
	"crypto/tls"

	"fmt"
	"net/smtp"
	"regexp"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/providercheck"

	awsCfg "github.com/aws/aws-sdk-go-v2/config"
	awsCreds "github.com/aws/aws-sdk-go-v2/credentials"
	sts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gofiber/fiber/v2"

	"github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type Handler struct {
	Service *Service
	log     *logger.Logger
}

func NewHandler(svc *Service, log *logger.Logger) *Handler {
	return &Handler{Service: svc, log: log}
}

func (h *Handler) GetConfig(c *fiber.Ctx) error {
	key := c.Params("key")
	if key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "key required"})
	}
	cfg, err := h.Service.Get(c.Context(), key)
	if err != nil {
		if isTableMissingErr(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "config not found"})
		}
		h.log.Error("server_config get failed", logger.ErrorField(err), logger.String("key", key))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "config not found"})
	}
	return c.JSON(cfg)
}

func (h *Handler) SetConfig(c *fiber.Ctx) error {

	var input struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := c.BodyParser(&input); err != nil || input.Key == "" {
		h.log.Error("server_config set failed", logger.ErrorField(err), logger.String("key", input.Key))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.Set(c.Context(), input.Key, input.Value, updatedBy.(string))
	if err != nil {
		if isTableMissingErr(err) {
			return c.JSON(fiber.Map{"key": input.Key, "value": input.Value, "version": 1, "updated_at": time.Now().UTC()})
		}
		h.log.Error("server_config set failed", logger.ErrorField(err), logger.String("key", input.Key))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Audit log

	return c.JSON(cfg)
}

func (h *Handler) ListConfig(c *fiber.Ctx) error {
	cfgs, err := h.Service.List(c.Context())
	if err != nil {
		if isTableMissingErr(err) {
			return c.JSON([]interface{}{})
		}
		h.log.Error("server_config list failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list config"})
	}
	return c.JSON(cfgs)
}

func (h *Handler) ConfigHistory(c *fiber.Ctx) error {
	key := c.Params("key")
	if key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "key required"})
	}
	history, err := h.Service.History(c.Context(), key)
	if err != nil {
		if isTableMissingErr(err) {
			return c.JSON([]interface{}{})
		}
		h.log.Error("server_config history failed", logger.ErrorField(err), logger.String("key", key))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get config history"})
	}
	return c.JSON(history)
}

func (h *Handler) ListMigrationStatus(c *fiber.Ctx) error {
	statuses, err := h.Service.ListMigrationStatus(c.Context())
	if err != nil {
		if isTableMissingErr(err) {
			return c.JSON([]interface{}{})
		}
		h.log.Error("migration status list failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list migration status"})
	}
	return c.JSON(statuses)
}

func (h *Handler) GetMigrationStatus(c *fiber.Ctx) error {
	name := c.Params("name")
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name required"})
	}
	status, err := h.Service.GetMigrationStatus(c.Context(), name)
	if err != nil {
		if isTableMissingErr(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "migration status not found"})
		}
		h.log.Error("migration status get failed", logger.ErrorField(err), logger.String("name", name))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "migration status not found"})
	}
	return c.JSON(status)
}

func (h *Handler) SetMigrationStatus(c *fiber.Ctx) error {
	var input MigrationStatus
	if err := c.BodyParser(&input); err != nil || input.Name == "" {
		h.log.Error("migration status set failed", logger.ErrorField(err), logger.String("name", input.Name))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	status, err := h.Service.SetMigrationStatus(c.Context(), &input)
	if err != nil {
		if isTableMissingErr(err) {
			return c.JSON(input)
		}
		h.log.Error("migration status set failed", logger.ErrorField(err), logger.String("name", input.Name))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Audit log

	return c.JSON(status)
}

// GetOwnerDBConfig returns the current owner-admin DB config (runtime, hot-reloadable)
func (h *Handler) GetOwnerDBConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerDBConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_db_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner db config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerDBConfig sets the owner-admin DB config (runtime, hot-reloadable)
func (h *Handler) SetOwnerDBConfig(c *fiber.Ctx) error {
	var input OwnerDBConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_db_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerDBConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_db_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Validate DB connection
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", input.User, input.Password, input.Host, input.Port, input.Name, input.SSLMode)
	dbpool, dbErr := pgxpool.New(c.Context(), dsn)
	if dbErr == nil {
		defer dbpool.Close()
		dbErr = dbpool.Ping(c.Context())
	}
	result := fiber.Map{"config": cfg, "db_connection_ok": dbErr == nil}
	if dbErr != nil {
		result["db_error"] = dbErr.Error()
	}
	return c.JSON(result)
}

// GetOwnerLoggingConfig returns the current owner-admin logging config (runtime, hot-reloadable)
func (h *Handler) GetOwnerLoggingConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerLoggingConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_logging_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner logging config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerLoggingConfig sets the owner-admin logging config (runtime, hot-reloadable)
func (h *Handler) SetOwnerLoggingConfig(c *fiber.Ctx) error {

	var input LoggingConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_logging_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerLoggingConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_logging_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

// GetOwnerJWTSecretConfig returns the current owner-admin JWT secret config (runtime, hot-reloadable)
func (h *Handler) GetOwnerJWTSecretConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerJWTSecretConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_jwt_secret_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner JWT secret config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerJWTSecretConfig sets the owner-admin JWT secret config (runtime, hot-reloadable)
func (h *Handler) SetOwnerJWTSecretConfig(c *fiber.Ctx) error {

	var input JWTSecretConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_jwt_secret_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerJWTSecretConfig(c.Context(), security_management.JWTSecretConfig{SecretName: input.SecretName}, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_jwt_secret_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Validate JWT secret using the helper function
	result := fiber.Map{"config": cfg, "jwt_secret_valid": false}
	if input.SecretName != "" {
		jwtConfig := &providercheck.JWTConfig{
			Secret: input.SecretName,
		}

		if err := providercheck.CheckJWTSecret(c.Context(), jwtConfig); err != nil {
			result["jwt_error"] = err.Error()
		} else {
			result["jwt_secret_valid"] = true
		}
	} else {
		result["jwt_error"] = "No JWT secret provided"
	}

	return c.JSON(result)
}

// GetOwnerOAuthConfig returns the current owner-admin OAuth config (runtime, hot-reloadable)
func (h *Handler) GetOwnerOAuthConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerOAuthConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_oauth_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner OAuth config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerOAuthConfig sets the owner-admin OAuth config (runtime, hot-reloadable)
func (h *Handler) SetOwnerOAuthConfig(c *fiber.Ctx) error {
	var input OAuthConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_oauth_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerOAuthConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_oauth_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Verify Google OAuth credentials using the helper function
	result := fiber.Map{"config": cfg, "google_oauth_valid": false}
	if input.Google.ClientID != "" && input.Google.ClientSecret != "" {
		oauthConfig := &providercheck.OAuthConfig{
			ClientID:     input.Google.ClientID,
			ClientSecret: input.Google.ClientSecret,
			RedirectURI:  input.Google.RedirectURI,
			Provider:     "google",
		}

		if err := providercheck.CheckOAuthCredentials(c.Context(), oauthConfig); err != nil {
			result["google_oauth_error"] = err.Error()
		} else {
			result["google_oauth_valid"] = true
		}
	} else {
		result["google_oauth_error"] = "Client ID or secret missing"
	}

	return c.JSON(result)
}

// GetOwnerSAMLConfig returns the current owner-admin SAML config (runtime, hot-reloadable)
func (h *Handler) GetOwnerSAMLConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerSAMLConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_saml_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner SAML config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerSAMLConfig sets the owner-admin SAML config (runtime, hot-reloadable)
func (h *Handler) SetOwnerSAMLConfig(c *fiber.Ctx) error {
	var input SAMLConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_saml_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerSAMLConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_saml_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Verify SAML metadata URL using the helper function
	result := fiber.Map{"config": cfg, "saml_metadata_valid": false}
	if input.MetadataURL != "" {
		samlConfig := &providercheck.SAMLConfig{
			MetadataURL: input.MetadataURL,
		}

		if err := providercheck.CheckSAMLMetadata(c.Context(), samlConfig); err != nil {
			result["saml_metadata_error"] = err.Error()
		} else {
			result["saml_metadata_valid"] = true
		}
	} else {
		result["saml_metadata_error"] = "No metadata URL provided"
	}

	return c.JSON(result)
}

// GetOwnerRedisConfig returns the current owner-admin Redis config (runtime, hot-reloadable)
func (h *Handler) GetOwnerRedisConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerRedisConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_redis_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner Redis config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerRedisConfig sets the owner-admin Redis config (runtime, hot-reloadable)
func (h *Handler) SetOwnerRedisConfig(c *fiber.Ctx) error {
	var input RedisConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_redis_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerRedisConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_redis_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Validate Redis connection
	addr := fmt.Sprintf("%s:%d", input.Host, input.Port)
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     input.Password,
		DB:           input.DB,
		PoolSize:     input.PoolSize,
		MinIdleConns: input.MinIdle,
	})
	ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
	defer cancel()
	pingErr := client.Ping(ctx).Err()
	_ = client.Close()
	result := fiber.Map{"config": cfg, "redis_connection_ok": pingErr == nil}
	if pingErr != nil {
		result["redis_error"] = pingErr.Error()
	}
	return c.JSON(result)
}

// GetOwnerAWSConfig returns the current owner-admin AWS config (runtime, hot-reloadable)
func (h *Handler) GetOwnerAWSConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerAWSConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_aws_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner AWS config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerAWSConfig sets the owner-admin AWS config (runtime, hot-reloadable)
func (h *Handler) SetOwnerAWSConfig(c *fiber.Ctx) error {
	var input AWSConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_aws_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerAWSConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_aws_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Test AWS connection (STS GetCallerIdentity)
	awsResult := fiber.Map{"config": cfg, "aws_connection_ok": false}
	ctx, cancel := context.WithTimeout(c.Context(), 3*time.Second)
	defer cancel()
	awsConfig, awsErr := awsCfg.LoadDefaultConfig(ctx,
		awsCfg.WithRegion(input.Region),
		awsCfg.WithCredentialsProvider(awsCreds.NewStaticCredentialsProvider(input.AccessKeyID, input.SecretAccessKey, input.SessionToken)),
	)
	if awsErr == nil {
		stsClient := sts.NewFromConfig(awsConfig)
		_, stsErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if stsErr == nil {
			awsResult["aws_connection_ok"] = true
		} else {
			awsResult["aws_error"] = "invalid credentials or role: " + stsErr.Error()
		}
	} else {
		awsResult["aws_error"] = "config error: " + awsErr.Error()
	}
	return c.JSON(awsResult)
}

// GetOwnerPaymentProviderConfig returns the current owner-admin payment provider config (runtime, hot-reloadable)
func (h *Handler) GetOwnerPaymentProviderConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerPaymentProviderConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_payment_provider_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner payment provider config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerPaymentProviderConfig sets the owner-admin payment provider config (runtime, hot-reloadable)
func (h *Handler) SetOwnerPaymentProviderConfig(c *fiber.Ctx) error {
	var input PaymentProviderConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_payment_provider_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerPaymentProviderConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_payment_provider_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Test payment provider connections (owner-level only, no tenant context here)
	results := fiber.Map{"config": cfg}
	providers := []string{"stripe", "paypal", "braintree"}
	pcfg := &providercheck.PaymentProviderConfig{
		StripeAPIKey:        input.StripeAPIKey,
		PaypalClientID:      input.PaypalClientID,
		PaypalClientSecret:  input.PaypalClientSecret,
		GooglePayMerchantID: input.GooglePayMerchantID,
		GooglePayAPIKey:     input.GooglePayAPIKey,
		ApplePayMerchantID:  input.ApplePayMerchantID,
		ApplePayAPIKey:      input.ApplePayAPIKey,
		PaymentsDisabled:    input.PaymentsDisabled,
		BraintreeMerchantID: input.BraintreeMerchantID,
		BraintreePublicKey:  input.BraintreePublicKey,
		BraintreePrivateKey: input.BraintreePrivateKey,
		BraintreeEnv:        input.BraintreeEnv,
	}
	for _, provider := range providers {
		err := providercheck.CheckPaymentProviderConnection(c.Context(), provider, pcfg)
		results[provider+"_connection_ok"] = err == nil
		if err != nil {
			results[provider+"_error"] = err.Error()
		}
	}
	return c.JSON(results)
}

// GetOwnerOpenAIConfig returns the current owner-admin OpenAI config (runtime, hot-reloadable)
func (h *Handler) GetOwnerOpenAIConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerOpenAIConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_openai_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner OpenAI config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerOpenAIConfig sets the owner-admin OpenAI config (runtime, hot-reloadable)
func (h *Handler) SetOwnerOpenAIConfig(c *fiber.Ctx) error {
	var input OpenAIConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_openai_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerOpenAIConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_openai_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Verify OpenAI API key using the helper function
	result := fiber.Map{"config": cfg, "openai_api_key_valid": false}
	if input.APIKey != "" {
		openaiConfig := &providercheck.OpenAIConfig{
			APIKey: input.APIKey,
			APIURL: input.APIURL,
		}

		if err := providercheck.CheckOpenAIAPIKey(c.Context(), openaiConfig); err != nil {
			result["openai_api_error"] = err.Error()
		} else {
			result["openai_api_key_valid"] = true
		}
	} else {
		result["openai_api_error"] = "No API key provided"
	}

	return c.JSON(result)
}

// GetOwnerAdminUserConfig returns the current owner-admin initial admin credentials (runtime, hot-reloadable)
func (h *Handler) GetOwnerAdminUserConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerAdminUserConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_admin_user_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner admin user config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerAdminUserConfig sets the owner-admin initial admin credentials (runtime, hot-reloadable)
func (h *Handler) SetOwnerAdminUserConfig(c *fiber.Ctx) error {
	var input AdminUserConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_admin_user_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerAdminUserConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_admin_user_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

// GetOwnerHashIDConfig returns the current owner-admin hashid salt (runtime, hot-reloadable)
func (h *Handler) GetOwnerHashIDConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerHashIDConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_hashid_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner hashid config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerHashIDConfig sets the owner-admin hashid salt (runtime, hot-reloadable)
func (h *Handler) SetOwnerHashIDConfig(c *fiber.Ctx) error {
	var input HashIDConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_hashid_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerHashIDConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_hashid_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

// GetOwnerCORSConfig returns the current owner-admin CORS config (runtime, hot-reloadable)
func (h *Handler) GetOwnerCORSConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerCORSConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_cors_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner CORS config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerCORSConfig sets the owner-admin CORS config (runtime, hot-reloadable)
func (h *Handler) SetOwnerCORSConfig(c *fiber.Ctx) error {
	var input CORSConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_cors_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerCORSConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_cors_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

// GetOwnerBillingConfig returns the current owner-admin billing config (runtime, hot-reloadable)
func (h *Handler) GetOwnerBillingConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerBillingConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_billing_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner billing config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerBillingConfig sets the owner-admin billing config (runtime, hot-reloadable)
func (h *Handler) SetOwnerBillingConfig(c *fiber.Ctx) error {
	var input BillingConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_billing_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerBillingConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_billing_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

// GetOwnerWebhookConfig returns the current owner-admin webhook config (runtime, hot-reloadable)
func (h *Handler) GetOwnerWebhookConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerWebhookConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_webhook_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner webhook config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerWebhookConfig sets the owner-admin webhook config (runtime, hot-reloadable)
func (h *Handler) SetOwnerWebhookConfig(c *fiber.Ctx) error {
	var input WebhookConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_webhook_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerWebhookConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_webhook_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Test webhook endpoint connectivity using the helper function
	result := fiber.Map{"config": cfg, "webhook_endpoint_reachable": false}
	if input.EventsURL != "" {
		webhookConfig := &providercheck.WebhookConfig{
			EndpointURL: input.EventsURL,
		}

		if err := providercheck.CheckWebhookEndpoint(c.Context(), webhookConfig); err != nil {
			result["webhook_error"] = err.Error()
		} else {
			result["webhook_endpoint_reachable"] = true
		}
	} else {
		result["webhook_error"] = "No webhook endpoint URL provided"
	}

	return c.JSON(result)
}

// GetOwnerSessionConfig returns the current owner-admin session config (runtime, hot-reloadable)
func (h *Handler) GetOwnerSessionConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerSessionConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_session_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner session config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerSessionConfig sets the owner-admin session config (runtime, hot-reloadable)
func (h *Handler) SetOwnerSessionConfig(c *fiber.Ctx) error {
	var input SessionConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_session_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerSessionConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_session_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(cfg)
}

// GetClientDBConfig returns the current client-admin DB config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientDBConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientDBConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_db_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client db config not found"})
	}
	return c.JSON(cfg)
}

// SetClientDBConfig sets the client-admin DB config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientDBConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientDBConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_db_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientDBConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_db_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Validate DB connection
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", input.User, input.Password, input.Host, input.Port, input.Name, input.SSLMode)
	dbpool, dbErr := pgxpool.New(c.Context(), dsn)
	if dbErr == nil {
		defer dbpool.Close()
		dbErr = dbpool.Ping(c.Context())
	}
	result := fiber.Map{"config": cfg, "db_connection_ok": dbErr == nil}
	if dbErr != nil {
		result["db_error"] = dbErr.Error()
	}
	return c.JSON(result)
}

// GetClientRedisConfig returns the current client-admin Redis config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientRedisConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientRedisConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_redis_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client redis config not found"})
	}
	return c.JSON(cfg)
}

// SetClientRedisConfig sets the client-admin Redis config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientRedisConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientRedisConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_redis_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientRedisConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_redis_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Validate Redis connection
	addr := fmt.Sprintf("%s:%d", input.Host, input.Port)
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     input.Password,
		DB:           input.DB,
		PoolSize:     input.PoolSize,
		MinIdleConns: input.MinIdle,
	})
	ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
	defer cancel()
	pingErr := client.Ping(ctx).Err()
	_ = client.Close()
	result := fiber.Map{"config": cfg, "redis_connection_ok": pingErr == nil}
	if pingErr != nil {
		result["redis_error"] = pingErr.Error()
	}
	return c.JSON(result)
}

// GetClientAWSConfig returns the current client-admin AWS config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientAWSConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientAWSConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_aws_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client aws config not found"})
	}
	return c.JSON(cfg)
}

// SetClientAWSConfig sets the client-admin AWS config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientAWSConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientAWSConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_aws_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientAWSConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_aws_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Test AWS connection (STS GetCallerIdentity)
	awsResult := fiber.Map{"config": cfg, "aws_connection_ok": false}
	ctx, cancel := context.WithTimeout(c.Context(), 3*time.Second)
	defer cancel()
	awsConfig, awsErr := awsCfg.LoadDefaultConfig(ctx,
		awsCfg.WithRegion(input.Region),
		awsCfg.WithCredentialsProvider(awsCreds.NewStaticCredentialsProvider(input.AccessKeyID, input.SecretAccessKey, input.SessionToken)),
	)
	if awsErr == nil {
		stsClient := sts.NewFromConfig(awsConfig)
		_, stsErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if stsErr == nil {
			awsResult["aws_connection_ok"] = true
		} else {
			awsResult["aws_error"] = "invalid credentials or role: " + stsErr.Error()
		}
	} else {
		awsResult["aws_error"] = "config error: " + awsErr.Error()
	}
	return c.JSON(awsResult)
}

// GetClientSMTPConfig returns the current client-admin SMTP config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientSMTPConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientSMTPConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_smtp_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client smtp config not found"})
	}
	return c.JSON(cfg)
}

// SetClientSMTPConfig sets the client-admin SMTP config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientSMTPConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientSMTPConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_smtp_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientSMTPConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_smtp_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Validate SMTP connection
	addr := fmt.Sprintf("%s:%d", input.Host, input.Port)
	var smtpErr error
	if input.UseSSL {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: false})
		if err != nil {
			smtpErr = err
		} else {
			c, err := smtp.NewClient(conn, input.Host)
			if err != nil {
				smtpErr = err
			} else {
				smtpErr = c.Quit()
			}
		}
	} else {
		c, err := smtp.Dial(addr)
		if err != nil {
			smtpErr = err
		} else {
			if input.UseTLS {
				smtpErr = c.StartTLS(&tls.Config{ServerName: input.Host, InsecureSkipVerify: false})
			}
			_ = c.Quit()
		}
	}
	result := fiber.Map{"config": cfg, "smtp_connection_ok": smtpErr == nil}
	if smtpErr != nil {
		result["smtp_error"] = smtpErr.Error()
	}
	return c.JSON(result)
}

// GetClientPaymentProviderConfig returns the current client-admin payment provider config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientPaymentProviderConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientPaymentProviderConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_payment_provider_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client payment provider config not found"})
	}
	return c.JSON(cfg)
}

// SetClientPaymentProviderConfig sets the client-admin payment provider config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientPaymentProviderConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientPaymentProviderConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_payment_provider_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientPaymentProviderConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_payment_provider_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	// Validate payment provider connections
	results := fiber.Map{"config": cfg}
	var providers []string
	if input.StripeAPIKey != "" {
		providers = append(providers, "stripe")
	}
	if input.PaypalClientID != "" && input.PaypalClientSecret != "" {
		providers = append(providers, "paypal")
	}
	if input.BraintreeMerchantID != "" && input.BraintreePublicKey != "" && input.BraintreePrivateKey != "" {
		providers = append(providers, "braintree")
	}
	pcfg := &providercheck.PaymentProviderConfig{
		StripeAPIKey:        input.StripeAPIKey,
		PaypalClientID:      input.PaypalClientID,
		PaypalClientSecret:  input.PaypalClientSecret,
		GooglePayMerchantID: input.GooglePayMerchantID,
		GooglePayAPIKey:     input.GooglePayAPIKey,
		ApplePayMerchantID:  input.ApplePayMerchantID,
		ApplePayAPIKey:      input.ApplePayAPIKey,
		PaymentsDisabled:    input.PaymentsDisabled,
		BraintreeMerchantID: input.BraintreeMerchantID,
		BraintreePublicKey:  input.BraintreePublicKey,
		BraintreePrivateKey: input.BraintreePrivateKey,
		BraintreeEnv:        input.BraintreeEnv,
	}
	for _, provider := range providers {
		err := providercheck.CheckPaymentProviderConnection(c.Context(), provider, pcfg)
		results[provider+"_connection_ok"] = err == nil
		if err != nil {
			results[provider+"_error"] = err.Error()
		}
	}
	return c.JSON(results)
}

// GetClientJWTSecretConfig returns the current client-admin JWT secret config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientJWTSecretConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientJWTSecretConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_jwt_secret_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client JWT secret config not found"})
	}
	return c.JSON(cfg)
}

// SetClientJWTSecretConfig sets the client-admin JWT secret config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientJWTSecretConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientJWTSecretConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_jwt_secret_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientJWTSecretConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_jwt_secret_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Validate JWT secret using the helper function
	result := fiber.Map{"config": cfg, "jwt_secret_valid": false}
	if input.SecretName != "" {
		jwtConfig := &providercheck.JWTConfig{
			Secret: input.SecretName,
		}

		if err := providercheck.CheckJWTSecret(c.Context(), jwtConfig); err != nil {
			result["jwt_error"] = err.Error()
		} else {
			result["jwt_secret_valid"] = true
		}
	} else {
		result["jwt_error"] = "No JWT secret provided"
	}

	return c.JSON(result)
}

// GetClientOAuthConfig returns the current client-admin OAuth config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientOAuthConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientOAuthConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_oauth_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client OAuth config not found"})
	}
	return c.JSON(cfg)
}

// SetClientOAuthConfig sets the client-admin OAuth config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientOAuthConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientOAuthConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_oauth_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientOAuthConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_oauth_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Verify Google OAuth credentials using the helper function
	result := fiber.Map{"config": cfg, "google_oauth_valid": false}
	if input.Google.ClientID != "" && input.Google.ClientSecret != "" {
		oauthConfig := &providercheck.OAuthConfig{
			ClientID:     input.Google.ClientID,
			ClientSecret: input.Google.ClientSecret,
			RedirectURI:  input.Google.RedirectURI,
			Provider:     "google",
		}

		if err := providercheck.CheckOAuthCredentials(c.Context(), oauthConfig); err != nil {
			result["google_oauth_error"] = err.Error()
		} else {
			result["google_oauth_valid"] = true
		}
	} else {
		result["google_oauth_error"] = "Client ID or secret missing"
	}

	return c.JSON(result)
}

// GetClientSAMLConfig returns the current client-admin SAML config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientSAMLConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientSAMLConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_saml_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client SAML config not found"})
	}
	return c.JSON(cfg)
}

// SetClientSAMLConfig sets the client-admin SAML config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientSAMLConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientSAMLConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_saml_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientSAMLConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_saml_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Verify SAML metadata URL using the helper function
	result := fiber.Map{"config": cfg, "saml_metadata_valid": false}
	if input.MetadataURL != "" {
		samlConfig := &providercheck.SAMLConfig{
			MetadataURL: input.MetadataURL,
		}

		if err := providercheck.CheckSAMLMetadata(c.Context(), samlConfig); err != nil {
			result["saml_metadata_error"] = err.Error()
		} else {
			result["saml_metadata_valid"] = true
		}
	} else {
		result["saml_metadata_error"] = "No metadata URL provided"
	}

	return c.JSON(result)
}

// GetClientOpenAIConfig returns the current client-admin OpenAI config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientOpenAIConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientOpenAIConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_openai_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client OpenAI config not found"})
	}
	return c.JSON(cfg)
}

// SetClientOpenAIConfig sets the client-admin OpenAI config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientOpenAIConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientOpenAIConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_openai_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientOpenAIConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_openai_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Verify OpenAI API key using the helper function
	result := fiber.Map{"config": cfg, "openai_api_key_valid": false}
	if input.APIKey != "" {
		openaiConfig := &providercheck.OpenAIConfig{
			APIKey: input.APIKey,
			APIURL: input.APIURL,
		}

		if err := providercheck.CheckOpenAIAPIKey(c.Context(), openaiConfig); err != nil {
			result["openai_api_error"] = err.Error()
		} else {
			result["openai_api_key_valid"] = true
		}
	} else {
		result["openai_api_error"] = "No API key provided"
	}

	return c.JSON(result)
}

// GetClientWebhookConfig returns the current client-admin webhook config for a tenant (runtime, hot-reloadable)
func (h *Handler) GetClientWebhookConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	cfg, err := h.Service.GetClientWebhookConfig(c.Context(), tenantID)
	if err != nil {
		h.log.Error("get_client_webhook_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "client webhook config not found"})
	}
	return c.JSON(cfg)
}

// SetClientWebhookConfig sets the client-admin webhook config for a tenant (runtime, hot-reloadable)
func (h *Handler) SetClientWebhookConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenantID")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenantID required"})
	}
	var input ClientWebhookConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_client_webhook_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetClientWebhookConfig(c.Context(), tenantID, input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_client_webhook_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Test webhook endpoint connectivity using the helper function
	result := fiber.Map{"config": cfg, "webhook_endpoint_reachable": false}
	if input.EventsURL != "" {
		webhookConfig := &providercheck.WebhookConfig{
			EndpointURL: input.EventsURL,
		}

		if err := providercheck.CheckWebhookEndpoint(c.Context(), webhookConfig); err != nil {
			result["webhook_error"] = err.Error()
		} else {
			result["webhook_endpoint_reachable"] = true
		}
	} else {
		result["webhook_error"] = "No webhook endpoint URL provided"
	}

	return c.JSON(result)
}

// GetOwnerSMTPConfig returns the current owner-admin SMTP config (runtime, hot-reloadable)
func (h *Handler) GetOwnerSMTPConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerSMTPConfig(c.Context())
	if err != nil {
		h.log.Error("get_owner_smtp_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "owner SMTP config not found"})
	}
	return c.JSON(cfg)
}

// SetOwnerSMTPConfig sets the owner-admin SMTP config (runtime, hot-reloadable)
func (h *Handler) SetOwnerSMTPConfig(c *fiber.Ctx) error {
	var input OwnerSMTPConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_smtp_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerSMTPConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_smtp_config failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	// Validate SMTP connection
	addr := fmt.Sprintf("%s:%d", input.Host, input.Port)
	var smtpErr error
	if input.UseSSL {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: false})
		if err != nil {
			smtpErr = err
		} else {
			sc, err := smtp.NewClient(conn, input.Host)
			if err != nil {
				smtpErr = err
			} else {
				smtpErr = sc.Quit()
			}
		}
	} else {
		sc, err := smtp.Dial(addr)
		if err != nil {
			smtpErr = err
		} else {
			if input.UseTLS {
				smtpErr = sc.StartTLS(&tls.Config{ServerName: input.Host, InsecureSkipVerify: false})
			}
			_ = sc.Quit()
		}
	}
	result := fiber.Map{"config": cfg, "smtp_connection_ok": smtpErr == nil}
	if smtpErr != nil {
		result["smtp_error"] = smtpErr.Error()
	}
	return c.JSON(result)
}

// isTableMissingErr returns true if the error is a missing table error (SQLSTATE 42P01)
func isTableMissingErr(err error) bool {
	if err == nil {
		return false
	}
	return (err.Error() == "ERROR: relation \"server_config\" does not exist (SQLSTATE 42P01)") ||
		(err.Error() == "ERROR: relation \"migration_status\" does not exist (SQLSTATE 42P01)")
}

func (h *Handler) GetOwnerGraphQLConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerGraphQLConfig(c.Context())
	if err != nil {
		h.log.Error("server_config get GraphQL failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get GraphQL config"})
	}
	return c.JSON(cfg)
}

func (h *Handler) SetOwnerGraphQLConfig(c *fiber.Ctx) error {
	var input GraphQLConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("server_config set GraphQL failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerGraphQLConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("server_config set GraphQL failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	return c.JSON(cfg)
}

// GetOwnerRBACConfig handles GET /owner-rbac-config
func (h *Handler) GetOwnerRBACConfig(c *fiber.Ctx) error {
	cfg, err := h.Service.GetOwnerRBACConfig(c.Context())
	if err != nil {
		h.log.Error("GetOwnerRBACConfig failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get RBAC config"})
	}
	return c.JSON(cfg)
}

// SetOwnerRBACConfig handles POST /owner-rbac-config
func (h *Handler) SetOwnerRBACConfig(c *fiber.Ctx) error {
	var cfg RBACConfig
	if err := c.BodyParser(&cfg); err != nil {
		h.log.Error("SetOwnerRBACConfig: parse failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid RBAC config format"})
	}

	// Validate the configuration
	// Compile bypass patterns to ensure they're valid regexes
	for _, pattern := range cfg.BypassPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("Invalid bypass pattern '%s': %v", pattern, err),
			})
		}
	}

	updatedBy := c.Get("X-User-ID", "system")
	if updatedBy == "" {
		updatedBy = "unknown"
	}

	result, err := h.Service.SetOwnerRBACConfig(c.Context(), cfg, updatedBy)
	if err != nil {
		h.log.Error("SetOwnerRBACConfig failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to set RBAC config"})
	}

	return c.JSON(result)
}
