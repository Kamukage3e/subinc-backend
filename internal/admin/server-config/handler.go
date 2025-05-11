package server_config

import (
	"github.com/gofiber/fiber/v2"
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
		h.log.Error("server_config set failed", logger.ErrorField(err), logger.String("key", input.Key))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *Handler) ListConfig(c *fiber.Ctx) error {
	cfgs, err := h.Service.List(c.Context())
	if err != nil {
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
		h.log.Error("server_config history failed", logger.ErrorField(err), logger.String("key", key))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get config history"})
	}
	return c.JSON(history)
}
