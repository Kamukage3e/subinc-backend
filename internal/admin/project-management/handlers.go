package project_management

import (
	"time"

	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (p *Project) Validate() error {
	if p.Name == "" {
		return errors.New("project name must not be empty")
	}
	if len(p.Name) > 128 {
		return errors.New("project name too long")
	}
	if p.OrgID == "" {
		return errors.New("org_id must not be empty")
	}
	return nil
}

func (h *ProjectHandler) CreateProject(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "create")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Project
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateProject: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateProject: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	proj, err := h.ProjectService.CreateProject(c.Context(), input)
	if err != nil {
		logger.LogError("CreateProject: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogger != nil {
		_, _ = h.SecurityAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "create_project",
			TargetID:  proj.ID,
			Details:   "Project created successfully",
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(proj)
}

func (h *ProjectHandler) UpdateProject(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "update")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Project
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateProject: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateProject: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	proj, err := h.ProjectService.UpdateProject(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateProject: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogger != nil {
		_, _ = h.SecurityAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_project",
			TargetID:  proj.ID,
			Details:   "Project updated successfully",
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(proj)
}

func (h *ProjectHandler) DeleteProject(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "delete")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteProject: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ProjectService.DeleteProject(c.Context(), input.ID); err != nil {
		logger.LogError("DeleteProject: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogger != nil {
		_, _ = h.SecurityAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "delete_project",
			TargetID:  input.ID,
			Details:   "Project deleted successfully",
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectHandler) GetProject(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "read")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetProject: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	proj, err := h.ProjectService.GetProject(c.Context(), input.ID)
	if err != nil {
		logger.LogError("GetProject: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(proj)
}

func (h *ProjectHandler) ListProjects(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "list")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		OrgID    string `json:"org_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListProjects: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	projs, err := h.ProjectService.ListProjects(c.Context(), input.OrgID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListProjects: failed", logger.ErrorField(err), logger.String("org_id", input.OrgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"projects": projs, "page": input.Page, "page_size": input.PageSize})
}

func (i *ProjectInvite) Validate() error {
	if i.ProjectID == "" {
		return errors.New("project_id must not be empty")
	}
	if i.Email == "" {
		return errors.New("email must not be empty")
	}
	if i.Role == "" {
		return errors.New("role must not be empty")
	}
	return nil
}

func (h *ProjectHandler) CreateInvite(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "invite")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input ProjectInvite
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvite: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateInvite: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	invite, err := h.ProjectInviteService.CreateInvite(c.Context(), input)
	if err != nil {
		logger.LogError("CreateInvite: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogger != nil {
		_, _ = h.SecurityAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "create_invite",
			TargetID:  input.ProjectID,
			Details:   "Invite created successfully",
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(invite)
}

func (h *ProjectHandler) AcceptInvite(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "accept_invite")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&input); err != nil || input.Token == "" {
		logger.LogError("AcceptInvite: token required", logger.String("token", input.Token))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token required"})
	}
	if err := h.ProjectInviteService.AcceptInvite(c.Context(), input.Token); err != nil {
		logger.LogError("AcceptInvite: failed", logger.ErrorField(err), logger.String("token", input.Token))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogger != nil {
		_, _ = h.SecurityAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "accept_invite",
			TargetID:  "",
			Details:   "Invite accepted successfully",
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectHandler) RevokeInvite(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "revoke_invite")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("RevokeInvite: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.ProjectInviteService.RevokeInvite(c.Context(), input.ID); err != nil {
		logger.LogError("RevokeInvite: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogger != nil {
		_, _ = h.SecurityAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "revoke_invite",
			TargetID:  input.ID,
			Details:   "Invite revoked successfully",
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProjectHandler) ListInvites(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "list_invites")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ProjectID string `json:"project_id"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListInvites: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	invites, err := h.ProjectInviteService.ListInvites(c.Context(), input.ProjectID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListInvites: failed", logger.ErrorField(err), logger.String("project_id", input.ProjectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"invites": invites, "page": input.Page, "page_size": input.PageSize})
}

func (h *ProjectHandler) GetSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "read")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ProjectID string `json:"project_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ProjectID == "" {
		logger.LogError("GetSettings: project_id required", logger.String("project_id", input.ProjectID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id required"})
	}
	settings, err := h.ProjectSettingsService.GetSettings(c.Context(), input.ProjectID)
	if err != nil {
		logger.LogError("GetSettings: failed", logger.ErrorField(err), logger.String("project_id", input.ProjectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(settings)
}

func (h *ProjectHandler) UpdateSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "project", "update")
		if err != nil || !permitted {
			logger.LogError("RBAC permission denied", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ProjectID string `json:"project_id"`
		Settings  string `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil || input.ProjectID == "" || input.Settings == "" {
		logger.LogError("UpdateSettings: missing required fields", logger.String("project_id", input.ProjectID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_id and settings required"})
	}
	if err := h.ProjectSettingsService.UpdateSettings(c.Context(), input.ProjectID, input.Settings); err != nil {
		logger.LogError("UpdateSettings: failed", logger.ErrorField(err), logger.String("project_id", input.ProjectID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogger != nil {
		_, _ = h.SecurityAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_settings",
			TargetID:  input.ProjectID,
			Details:   "Settings updated successfully",
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
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
