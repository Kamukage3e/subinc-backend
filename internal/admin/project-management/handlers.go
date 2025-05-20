package project_management

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewProjectHandler(store *PostgresStore) *ProjectHandler {
	return &ProjectHandler{
		Store:                  store,
		ProjectService:         store,
		ProjectSettingsService: store,
		RateLimitService:       nil, // This will be set by the router
	}
}

func (p *Project) Validate() error {
	if p.Name == "" {
		return errors.New("project name must not be empty")
	}
	if len(p.Name) > 128 {
		return errors.New("project name too long")
	}
	return nil
}

func (h *ProjectHandler) CreateProject(c *fiber.Ctx) error {

	var input Project
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateProject: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateProject: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	// Initialize tags if nil
	if input.Tags == nil {
		input.Tags = make(map[string]string)
	}

	// Set default status if empty
	if input.Status == "" {
		input.Status = "active"
	}

	proj, err := h.ProjectService.CreateProject(c.Context(), input)
	if err != nil {
		logger.LogError("CreateProject: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(proj)
}

func (h *ProjectHandler) UpdateProject(c *fiber.Ctx) error {

	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateProject: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input Project
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateProject: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateProject: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	proj, err := h.ProjectService.UpdateProject(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateProject: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(proj)
}

func (h *ProjectHandler) DeleteProject(c *fiber.Ctx) error {

	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteProject: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ProjectService.DeleteProject(c.Context(), id); err != nil {
		logger.LogError("DeleteProject: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectHandler) GetProject(c *fiber.Ctx) error {

	id := c.Params("id")
	if id == "" {
		logger.LogError("GetProject: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	proj, err := h.ProjectService.GetProject(c.Context(), id)
	if err != nil {
		logger.LogError("GetProject: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(proj)
}

func (h *ProjectHandler) ListProjects(c *fiber.Ctx) error {

	orgID := c.Query("org_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	projs, err := h.ProjectService.ListProjects(c.Context(), orgID, page, pageSize)
	if err != nil {
		logger.LogError("ListProjects: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"projects": projs, "page": page, "page_size": pageSize})
}

func (h *ProjectHandler) GetSettings(c *fiber.Ctx) error {

	id := c.Params("id")
	if id == "" {
		logger.LogError("GetSettings: project_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id required"})
	}
	settings, err := h.ProjectSettingsService.GetSettings(c.Context(), id)
	if err != nil {
		logger.LogError("GetSettings: failed", logger.ErrorField(err), logger.String("project_id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if settings == nil {
		settings = map[string]interface{}{}
	}
	return c.JSON(fiber.Map{"settings": settings})
}

func (h *ProjectHandler) UpdateSettings(c *fiber.Ctx) error {

	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateSettings: project_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id required"})
	}
	var input struct {
		Settings map[string]interface{} `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil || input.Settings == nil {
		logger.LogError("UpdateSettings: missing required fields", logger.String("project_id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "settings required"})
	}
	updated, err := h.ProjectSettingsService.UpdateSettings(c.Context(), id, input.Settings)
	if err != nil {
		logger.LogError("UpdateSettings: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"settings": updated})
}

// getActorID extracts the actor/user id from the request context or headers for audit logging
func getActorID(c *fiber.Ctx) string {
	id := c.Get("X-Actor-ID")
	if id != "" {
		return id
	}
	id = c.Get("X-User-ID")
	if id != "" {
		return id
	}
	return ""
}
