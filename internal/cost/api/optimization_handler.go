package api

import (
	"net/http"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/service"
)

func NewOptimizationHandler(svc *service.OptimizationService) *OptimizationHandler {
	return &OptimizationHandler{service: svc}
}

// POST /optimization/recommendations
func (h *OptimizationHandler) GenerateRecommendations(c *fiber.Ctx) error {
	var req domain.OptimizationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request payload"})
	}
	ctx := c.Context()
	recs, err := h.service.GenerateRecommendations(ctx, &req)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"recommendations": recs})
}

// GET /optimization/recommendations/:id
func (h *OptimizationHandler) GetRecommendation(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing id"})
	}
	ctx := c.Context()
	rec, err := h.service.GetRecommendation(ctx, id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not found"})
	}
	return c.Status(http.StatusOK).JSON(rec)
}

// GET /optimization/history
func (h *OptimizationHandler) ListHistory(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	projectID := c.Query("project_id")
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	ctx := c.Context()
	recs, total, err := h.service.ListHistory(ctx, tenantID, projectID, limit, offset)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"recommendations": recs, "total": total})
}
