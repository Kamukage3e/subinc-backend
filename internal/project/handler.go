package project

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/idencode"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewHandler(service Service, log *logger.Logger) *Handler {
	return &Handler{service: service, log: log}
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
	claims := c.Locals("user")
	userID := ""
	if claimsMap, ok := claims.(map[string]interface{}); ok {
		if sub, ok := claimsMap["sub"].(string); ok {
			userID = sub
		}
	}
	if userID == "" {
		h.log.Error("missing user context for project creation")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: missing user context"})
	}
	out, err := h.service.Create(context.Background(), req)
	if err != nil {
		h.log.Error("failed to create project", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	// Assign creator as project owner (admin)
	userStore, ok := h.service.(interface {
		AssignProjectOwner(ctx context.Context, userID, projectID string) error
	})
	if !ok {
		h.log.Error("service does not support AssignProjectOwner")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal error: role assignment not supported"})
	}
	if err := userStore.AssignProjectOwner(context.Background(), userID, out.Project.ID); err != nil {
		h.log.Error("failed to assign project owner role", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to assign project owner role"})
	}
	idHash, _ := idencode.Encode(out.Project.ID)
	out.Project.ID = idHash
	return c.Status(http.StatusCreated).JSON(out.Project)
}

func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := decodeProjectIDParam(c)
	if err != nil {
		h.log.Error("failed to decode project id", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid project id"})
	}
	out, err := h.service.Get(context.Background(), GetProjectInput{ID: id})
	if err != nil {
		h.log.Error("failed to get project", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	idHash, _ := idencode.Encode(out.Project.ID)
	out.Project.ID = idHash
	return c.JSON(out.Project)
}

func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := decodeProjectIDParam(c)
	if err != nil {
		h.log.Error("failed to decode project id", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid project id"})
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
	idHash, _ := idencode.Encode(out.Project.ID)
	out.Project.ID = idHash
	return c.JSON(out.Project)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := decodeProjectIDParam(c)
	if err != nil {
		h.log.Error("failed to decode project id", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid project id"})
	}
	_, err = h.service.Delete(context.Background(), DeleteProjectInput{ID: id})
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
	for _, p := range out.Projects {
		idHash, _ := idencode.Encode(p.ID)
		p.ID = idHash
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
	for _, p := range out.Projects {
		idHash, _ := idencode.Encode(p.ID)
		p.ID = idHash
	}
	return c.JSON(out.Projects)
}

func (h *Handler) TransferProject(c *fiber.Ctx) error {
	projectID, err := decodeProjectIDParam(c)
	if err != nil {
		h.log.Error("failed to decode project id", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid project id"})
	}
	var req struct {
		NewOwnerID string `json:"new_owner_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.NewOwnerID == "" {
		h.log.Error("invalid transfer project request", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "new_owner_id required"})
	}
	claims := c.Locals("user")
	actorID := ""
	if claimsMap, ok := claims.(map[string]interface{}); ok {
		if sub, ok := claimsMap["sub"].(string); ok {
			actorID = sub
		}
	}
	if actorID == "" {
		h.log.Error("missing user context for project transfer")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: missing user context"})
	}
	if err := h.service.TransferProjectOwner(context.Background(), actorID, projectID, req.NewOwnerID); err != nil {
		h.log.Error("failed to transfer project ownership", logger.ErrorField(err))
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"success": true})
}

func (h *Handler) TransferUserToProject(c *fiber.Ctx) error {
	var req struct {
		UserID        string `json:"user_id"`
		FromProjectID string `json:"from_project_id"`
		ToProjectID   string `json:"to_project_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.FromProjectID == "" || req.ToProjectID == "" {
		h.log.Error("invalid transfer user to project request", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "user_id, from_project_id, to_project_id required"})
	}
	claims := c.Locals("user")
	actorID := ""
	if claimsMap, ok := claims.(map[string]interface{}); ok {
		if sub, ok := claimsMap["sub"].(string); ok {
			actorID = sub
		}
	}
	if actorID == "" {
		h.log.Error("missing user context for user transfer")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: missing user context"})
	}
	if err := h.service.TransferUserToProject(context.Background(), actorID, req.UserID, req.FromProjectID, req.ToProjectID); err != nil {
		h.log.Error("failed to transfer user between projects", logger.ErrorField(err))
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"success": true})
}

func (h *Handler) ListProjectUsers(c *fiber.Ctx) error {
	projectID, err := decodeProjectIDParam(c)
	if err != nil {
		h.log.Error("failed to decode project id", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid project id"})
	}
	claims := c.Locals("user")
	actorID := ""
	if claimsMap, ok := claims.(map[string]interface{}); ok {
		if sub, ok := claimsMap["sub"].(string); ok {
			actorID = sub
		}
	}
	if actorID == "" {
		h.log.Error("missing user context for list project users")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: missing user context"})
	}
	users, err := h.service.ListProjectUsers(context.Background(), actorID, projectID)
	if err != nil {
		h.log.Error("failed to list project users", logger.ErrorField(err))
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusOK).JSON(users)
}

func (h *Handler) AddUserToProject(c *fiber.Ctx) error {
	projectID, err := decodeProjectIDParam(c)
	if err != nil {
		h.log.Error("failed to decode project id", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid project id"})
	}
	var req struct {
		UserID string   `json:"user_id"`
		Role   string   `json:"role"`
		Perms  []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.Role == "" {
		h.log.Error("invalid add user to project request", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "user_id and role required"})
	}
	claims := c.Locals("user")
	actorID := ""
	if claimsMap, ok := claims.(map[string]interface{}); ok {
		if sub, ok := claimsMap["sub"].(string); ok {
			actorID = sub
		}
	}
	if actorID == "" {
		h.log.Error("missing user context for add user to project")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: missing user context"})
	}
	if err := h.service.AddUserToProject(context.Background(), actorID, projectID, req.UserID, req.Role, req.Perms); err != nil {
		h.log.Error("failed to add user to project", logger.ErrorField(err))
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"success": true})
}

func (h *Handler) RemoveUserFromProject(c *fiber.Ctx) error {
	projectID, err := decodeProjectIDParam(c)
	if err != nil {
		h.log.Error("failed to decode project id", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid project id"})
	}
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		h.log.Error("invalid remove user from project request", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "user_id required"})
	}
	claims := c.Locals("user")
	actorID := ""
	if claimsMap, ok := claims.(map[string]interface{}); ok {
		if sub, ok := claimsMap["sub"].(string); ok {
			actorID = sub
		}
	}
	if actorID == "" {
		h.log.Error("missing user context for remove user from project")
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: missing user context"})
	}
	if err := h.service.RemoveUserFromProject(context.Background(), actorID, projectID, req.UserID); err != nil {
		h.log.Error("failed to remove user from project", logger.ErrorField(err))
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"success": true})
}

func decodeProjectIDParam(c *fiber.Ctx) (string, error) {
	return idencode.Decode(c.Params("id"))
}
