package server_config

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set")
		if err != nil || !permitted {
			h.log.Error("SetConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// Audit log
	if h.Service.AuditLogger != nil {
		details, _ := json.Marshal(input)
		go h.Service.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   updatedBy.(string),
			Action:    "set_server_config",
			TargetID:  input.Key,
			Details:   string(details),
			CreatedAt: time.Now().UTC(),
		})
	}
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "migration_status", "set")
		if err != nil || !permitted {
			h.log.Error("SetMigrationStatus: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// Audit log
	if h.Service.AuditLogger != nil {
		details, _ := json.Marshal(input)
		actor := c.Locals("actor_id")
		if actor == nil {
			actor = "system"
		}
		go h.Service.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   actor.(string),
			Action:    "set_migration_status",
			TargetID:  input.Name,
			Details:   string(details),
			CreatedAt: time.Now().UTC(),
		})
	}
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_db_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerDBConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_logging_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerLoggingConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_jwt_secret_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerJWTSecretConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input JWTSecretConfig
	if err := c.BodyParser(&input); err != nil {
		h.log.Error("set_owner_jwt_secret_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	updatedBy := c.Locals("actor_id")
	if updatedBy == nil {
		updatedBy = "system"
	}
	cfg, err := h.Service.SetOwnerJWTSecretConfig(c.Context(), input, updatedBy.(string))
	if err != nil {
		h.log.Error("set_owner_jwt_secret_config failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_oauth_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerOAuthConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_saml_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerSAMLConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_redis_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerRedisConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_aws_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerAWSConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_payment_provider_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerPaymentProviderConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_openai_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerOpenAIConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_admin_user_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerAdminUserConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_hashid_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerHashIDConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_cors_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerCORSConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_billing_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerBillingConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_webhook_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerWebhookConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
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
	if h.Service.RBACService != nil {
		actorID := c.Locals("actor_id")
		if actorID == nil {
			actorID = "system"
		}
		permitted, err := h.Service.RBACService.CheckPermission(c.Context(), actorID.(string), "server_config", "set_owner_session_config")
		if err != nil || !permitted {
			h.log.Error("SetOwnerSessionConfig: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID.(string)))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

// isTableMissingErr returns true if the error is a missing table error (SQLSTATE 42P01)
func isTableMissingErr(err error) bool {
	if err == nil {
		return false
	}
	return (err.Error() == "ERROR: relation \"server_config\" does not exist (SQLSTATE 42P01)") ||
		(err.Error() == "ERROR: relation \"migration_status\" does not exist (SQLSTATE 42P01)")
}
