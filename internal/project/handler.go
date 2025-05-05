package project

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type Handler struct {
	service Service
	log     *logger.Logger
}

func NewHandler(service Service, log *logger.Logger) *Handler {
	return &Handler{service: service, log: log}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	router.Post("/projects", h.Create)
	router.Get("/projects/:id", h.Get)
	router.Put("/projects/:id", h.Update)
	router.Delete("/projects/:id", h.Delete)
	router.Get("/tenants/:tenant_id/projects", h.ListByTenant)
	router.Get("/orgs/:org_id/projects", h.ListByOrg)
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var req CreateProjectInput
	if err := c.BodyParser(&req); err != nil {
		h.log.Error("invalid create project request", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if req.ID == "" {
		req.ID = uuid.NewString()
	}
	out, err := h.service.Create(context.Background(), req)
	if err != nil {
		h.log.Error("failed to create project", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusCreated).JSON(out.Project)
}

func (h *Handler) Get(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing project id"})
	}
	out, err := h.service.Get(context.Background(), GetProjectInput{ID: id})
	if err != nil {
		h.log.Error("failed to get project", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out.Project)
}

func (h *Handler) Update(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing project id"})
	}
	var req UpdateProjectInput
	if err := c.BodyParser(&req); err != nil {
		h.log.Error("invalid update project request", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	req.ID = id
	out, err := h.service.Update(context.Background(), req)
	if err != nil {
		h.log.Error("failed to update project", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out.Project)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing project id"})
	}
	_, err := h.service.Delete(context.Background(), DeleteProjectInput{ID: id})
	if err != nil {
		h.log.Error("failed to delete project", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *Handler) ListByTenant(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing tenant id"})
	}
	out, err := h.service.ListByTenant(context.Background(), ListProjectsByTenantInput{TenantID: tenantID})
	if err != nil {
		h.log.Error("failed to list projects by tenant", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out.Projects)
}

func (h *Handler) ListByOrg(c *fiber.Ctx) error {
	orgID := c.Params("org_id")
	if orgID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing org id"})
	}
	out, err := h.service.ListByOrg(context.Background(), ListProjectsByOrgInput{OrgID: orgID})
	if err != nil {
		h.log.Error("failed to list projects by org", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out.Projects)
}
