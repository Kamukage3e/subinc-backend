package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type AnomalyHandler struct {
	anomalyService service.AnomalyDetectionService
	logger         *logger.Logger
}

func NewAnomalyHandler(anomalyService service.AnomalyDetectionService, log *logger.Logger) *AnomalyHandler {
	if log == nil {
		log = logger.NewNoop()
	}
	return &AnomalyHandler{anomalyService: anomalyService, logger: log}
}

// POST /api/v1/anomalies/detect
func (h *AnomalyHandler) DetectAnomalies(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	var req struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if err := c.BodyParser(&req); err != nil {
		h.logger.Error("invalid request body", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	start, err := time.Parse(time.RFC3339, req.Start)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid start time"})
	}
	end, err := time.Parse(time.RFC3339, req.End)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid end time"})
	}
	anomalies, err := h.anomalyService.DetectAnomalies(context.Background(), tenantID, start, end)
	if err != nil {
		h.logger.Error("anomaly detection failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "anomaly detection failed"})
	}
	return c.JSON(fiber.Map{"anomalies": anomalies})
}

// GET /api/v1/anomalies
func (h *AnomalyHandler) ListAnomalies(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	filter := service.AnomalyFilter{
		Provider: domain.CloudProvider(c.Query("provider")),
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
		Page:     c.QueryInt("page", 1),
		Size:     c.QueryInt("size", 50),
	}
	if from := c.Query("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			filter.From = t
		}
	}
	if to := c.Query("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			filter.To = t
		}
	}
	anomalies, total, err := h.anomalyService.ListAnomalies(context.Background(), tenantID, filter)
	if err != nil {
		h.logger.Error("failed to list anomalies", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list anomalies"})
	}
	return c.JSON(fiber.Map{"anomalies": anomalies, "total": total})
}

// GET /api/v1/anomalies/:id/recommendation
func (h *AnomalyHandler) GetRecommendation(c *fiber.Ctx) error {
	anomalyID := c.Params("id")
	rec, err := h.anomalyService.GetRecommendations(context.Background(), anomalyID)
	if err != nil {
		h.logger.Error("failed to get recommendation", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get recommendation"})
	}
	return c.JSON(fiber.Map{"recommendation": rec})
}
