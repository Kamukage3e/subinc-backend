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

// isTableMissingErr returns true if the error is a missing table error (SQLSTATE 42P01)
func isTableMissingErr(err error) bool {
	if err == nil {
		return false
	}
	return (err.Error() == "ERROR: relation \"server_config\" does not exist (SQLSTATE 42P01)") ||
		(err.Error() == "ERROR: relation \"migration_status\" does not exist (SQLSTATE 42P01)")
}
