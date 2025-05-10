package project_management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type ProjectAdminHandler struct {
	ProjectService         ProjectService
	ProjectMemberService   ProjectMemberService
	ProjectInviteService   ProjectInviteService
	ProjectSettingsService ProjectSettingsService
	ProjectAuditLogService ProjectAuditLogService
	Store                  *PostgresStore
}

func (h *ProjectAdminHandler) CreateProject(c *fiber.Ctx) error {
	var input Project
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateProject: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	proj, err := h.ProjectService.CreateProject(c.Context(), input)
	if err != nil {
		logger.LogError("CreateProject: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(proj)
}

func (h *ProjectAdminHandler) UpdateProject(c *fiber.Ctx) error {
	var input Project
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateProject: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	proj, err := h.ProjectService.UpdateProject(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateProject: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(proj)
}

func (h *ProjectAdminHandler) DeleteProject(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteProject: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ProjectService.DeleteProject(c.Context(), id); err != nil {
		logger.LogError("DeleteProject: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectAdminHandler) GetProject(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetProject: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	proj, err := h.ProjectService.GetProject(c.Context(), id)
	if err != nil {
		logger.LogError("GetProject: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(proj)
}

func (h *ProjectAdminHandler) ListProjects(c *fiber.Ctx) error {
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

func (h *ProjectAdminHandler) AddMember(c *fiber.Ctx) error {
	var input ProjectMember
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("AddMember: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ProjectID == "" || input.UserID == "" || input.Role == "" {
		logger.LogError("AddMember: missing required fields", logger.Any("input", input))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id, user_id, and role required"})
	}
	member, err := h.ProjectMemberService.AddMember(c.Context(), input)
	if err != nil {
		logger.LogError("AddMember: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(member)
}

func (h *ProjectAdminHandler) RemoveMember(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("RemoveMember: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ProjectMemberService.RemoveMember(c.Context(), id); err != nil {
		logger.LogError("RemoveMember: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectAdminHandler) UpdateMember(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateMember: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input ProjectMember
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateMember: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	member, err := h.ProjectMemberService.UpdateMember(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateMember: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(member)
}

func (h *ProjectAdminHandler) GetMember(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetMember: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	member, err := h.ProjectMemberService.GetMember(c.Context(), id)
	if err != nil {
		logger.LogError("GetMember: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(member)
}

func (h *ProjectAdminHandler) ListMembers(c *fiber.Ctx) error {
	projectID := c.Query("project_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	members, err := h.ProjectMemberService.ListMembers(c.Context(), projectID, page, pageSize)
	if err != nil {
		logger.LogError("ListMembers: failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"members": members, "page": page, "page_size": pageSize})
}

func (h *ProjectAdminHandler) CreateInvite(c *fiber.Ctx) error {
	var input ProjectInvite
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvite: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ProjectID == "" || input.Email == "" || input.Role == "" {
		logger.LogError("CreateInvite: missing required fields", logger.Any("input", input))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id, email, and role required"})
	}
	invite, err := h.ProjectInviteService.CreateInvite(c.Context(), input)
	if err != nil {
		logger.LogError("CreateInvite: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(invite)
}

func (h *ProjectAdminHandler) AcceptInvite(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		logger.LogError("AcceptInvite: token required", logger.String("token", token))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token required"})
	}
	if err := h.ProjectInviteService.AcceptInvite(c.Context(), token); err != nil {
		logger.LogError("AcceptInvite: failed", logger.ErrorField(err), logger.String("token", token))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectAdminHandler) RevokeInvite(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("RevokeInvite: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ProjectInviteService.RevokeInvite(c.Context(), id); err != nil {
		logger.LogError("RevokeInvite: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectAdminHandler) ListInvites(c *fiber.Ctx) error {
	projectID := c.Query("project_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	invites, err := h.ProjectInviteService.ListInvites(c.Context(), projectID, page, pageSize)
	if err != nil {
		logger.LogError("ListInvites: failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"invites": invites, "page": page, "page_size": pageSize})
}

func (h *ProjectAdminHandler) GetSettings(c *fiber.Ctx) error {
	projectID := c.Query("project_id")
	if projectID == "" {
		logger.LogError("GetSettings: project_id required", logger.String("project_id", projectID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id required"})
	}
	settings, err := h.ProjectSettingsService.GetSettings(c.Context(), projectID)
	if err != nil {
		logger.LogError("GetSettings: failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(settings)
}

func (h *ProjectAdminHandler) UpdateSettings(c *fiber.Ctx) error {
	projectID := c.Query("project_id")
	var input struct {
		Settings string `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if projectID == "" || input.Settings == "" {
		logger.LogError("UpdateSettings: missing required fields", logger.String("project_id", projectID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id and settings required"})
	}
	if err := h.ProjectSettingsService.UpdateSettings(c.Context(), projectID, input.Settings); err != nil {
		logger.LogError("UpdateSettings: failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectAdminHandler) CreateAuditLog(c *fiber.Ctx) error {
	var input ProjectAuditLog
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAuditLog: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	logEntry, err := h.ProjectAuditLogService.CreateAuditLog(c.Context(), input)
	if err != nil {
		logger.LogError("CreateAuditLog: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(logEntry)
}

func (h *ProjectAdminHandler) ListAuditLogs(c *fiber.Ctx) error {
	projectID := c.Query("project_id")
	actorID := c.Query("actor_id")
	action := c.Query("action")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.ProjectAuditLogService.ListAuditLogs(c.Context(), projectID, actorID, action, page, pageSize)
	if err != nil {
		logger.LogError("ListAuditLogs: failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}
