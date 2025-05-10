package organization_management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type OrganizationAdminHandler struct {
	OrganizationService OrganizationService
	OrgMemberService    OrgMemberService
	OrgInviteService    OrgInviteService
	OrgDomainService    OrgDomainService
	OrgSettingsService  OrgSettingsService
	OrgAuditLogService  OrgAuditLogService
	Store               *PostgresStore
}

func (h *OrganizationAdminHandler) CreateOrganization(c *fiber.Ctx) error {
	var input Organization
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateOrganization: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	org, err := h.OrganizationService.CreateOrganization(c.Context(), input)
	if err != nil {
		logger.LogError("CreateOrganization: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(org)
}

func (h *OrganizationAdminHandler) UpdateOrganization(c *fiber.Ctx) error {
	var input Organization
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateOrganization: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	org, err := h.OrganizationService.UpdateOrganization(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateOrganization: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(org)
}

func (h *OrganizationAdminHandler) DeleteOrganization(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteOrganization: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.OrganizationService.DeleteOrganization(c.Context(), id); err != nil {
		logger.LogError("DeleteOrganization: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationAdminHandler) GetOrganization(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetOrganization: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	org, err := h.OrganizationService.GetOrganization(c.Context(), id)
	if err != nil {
		logger.LogError("GetOrganization: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(org)
}

func (h *OrganizationAdminHandler) ListOrganizations(c *fiber.Ctx) error {
	ownerID := c.Query("owner_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	orgs, err := h.OrganizationService.ListOrganizations(c.Context(), ownerID, page, pageSize)
	if err != nil {
		logger.LogError("ListOrganizations: failed", logger.ErrorField(err), logger.String("owner_id", ownerID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"organizations": orgs, "page": page, "page_size": pageSize})
}

func (h *OrganizationAdminHandler) AddMember(c *fiber.Ctx) error {
	var input OrgMember
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("AddMember: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.OrgID == "" || input.UserID == "" || input.Role == "" {
		logger.LogError("AddMember: missing required fields", logger.Any("input", input))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id, user_id, and role required"})
	}
	member, err := h.OrgMemberService.AddMember(c.Context(), input)
	if err != nil {
		logger.LogError("AddMember: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(member)
}

func (h *OrganizationAdminHandler) RemoveMember(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("RemoveMember: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.OrgMemberService.RemoveMember(c.Context(), id); err != nil {
		logger.LogError("RemoveMember: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationAdminHandler) UpdateMember(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateMember: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input OrgMember
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateMember: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	member, err := h.OrgMemberService.UpdateMember(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateMember: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(member)
}

func (h *OrganizationAdminHandler) GetMember(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetMember: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	member, err := h.OrgMemberService.GetMember(c.Context(), id)
	if err != nil {
		logger.LogError("GetMember: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(member)
}

func (h *OrganizationAdminHandler) ListMembers(c *fiber.Ctx) error {
	orgID := c.Query("org_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	members, err := h.OrgMemberService.ListMembers(c.Context(), orgID, page, pageSize)
	if err != nil {
		logger.LogError("ListMembers: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"members": members, "page": page, "page_size": pageSize})
}

func (h *OrganizationAdminHandler) CreateInvite(c *fiber.Ctx) error {
	var input OrgInvite
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvite: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.OrgID == "" || input.Email == "" || input.Role == "" {
		logger.LogError("CreateInvite: missing required fields", logger.Any("input", input))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id, email, and role required"})
	}
	invite, err := h.OrgInviteService.CreateInvite(c.Context(), input)
	if err != nil {
		logger.LogError("CreateInvite: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(invite)
}

func (h *OrganizationAdminHandler) AcceptInvite(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		logger.LogError("AcceptInvite: token required", logger.String("token", token))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token required"})
	}
	if err := h.OrgInviteService.AcceptInvite(c.Context(), token); err != nil {
		logger.LogError("AcceptInvite: failed", logger.ErrorField(err), logger.String("token", token))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationAdminHandler) RevokeInvite(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("RevokeInvite: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.OrgInviteService.RevokeInvite(c.Context(), id); err != nil {
		logger.LogError("RevokeInvite: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationAdminHandler) ListInvites(c *fiber.Ctx) error {
	orgID := c.Query("org_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	invites, err := h.OrgInviteService.ListInvites(c.Context(), orgID, page, pageSize)
	if err != nil {
		logger.LogError("ListInvites: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"invites": invites, "page": page, "page_size": pageSize})
}

func (h *OrganizationAdminHandler) AddDomain(c *fiber.Ctx) error {
	var input OrgDomain
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("AddDomain: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.OrgID == "" || input.Domain == "" {
		logger.LogError("AddDomain: missing required fields", logger.Any("input", input))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id and domain required"})
	}
	domain, err := h.OrgDomainService.AddDomain(c.Context(), input)
	if err != nil {
		logger.LogError("AddDomain: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(domain)
}

func (h *OrganizationAdminHandler) VerifyDomain(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("VerifyDomain: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.OrgDomainService.VerifyDomain(c.Context(), id); err != nil {
		logger.LogError("VerifyDomain: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationAdminHandler) RemoveDomain(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("RemoveDomain: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.OrgDomainService.RemoveDomain(c.Context(), id); err != nil {
		logger.LogError("RemoveDomain: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationAdminHandler) ListDomains(c *fiber.Ctx) error {
	orgID := c.Query("org_id")
	domains, err := h.OrgDomainService.ListDomains(c.Context(), orgID)
	if err != nil {
		logger.LogError("ListDomains: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"domains": domains})
}

func (h *OrganizationAdminHandler) GetSettings(c *fiber.Ctx) error {
	orgID := c.Query("org_id")
	settings, err := h.OrgSettingsService.GetSettings(c.Context(), orgID)
	if err != nil {
		logger.LogError("GetSettings: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(settings)
}

func (h *OrganizationAdminHandler) UpdateSettings(c *fiber.Ctx) error {
	orgID := c.Query("org_id")
	var input struct {
		Settings string `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if orgID == "" || input.Settings == "" {
		logger.LogError("UpdateSettings: missing required fields", logger.String("org_id", orgID), logger.String("settings", input.Settings))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id and settings required"})
	}
	if err := h.OrgSettingsService.UpdateSettings(c.Context(), orgID, input.Settings); err != nil {
		logger.LogError("UpdateSettings: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationAdminHandler) CreateAuditLog(c *fiber.Ctx) error {
	var input OrgAuditLog
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAuditLog: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	log, err := h.OrgAuditLogService.CreateAuditLog(c.Context(), input)
	if err != nil {
		logger.LogError("CreateAuditLog: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(log)
}

func (h *OrganizationAdminHandler) ListAuditLogs(c *fiber.Ctx) error {
	orgID := c.Query("org_id")
	actorID := c.Query("actor_id")
	action := c.Query("action")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.OrgAuditLogService.ListAuditLogs(c.Context(), orgID, actorID, action, page, pageSize)
	if err != nil {
		logger.LogError("ListAuditLogs: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}
