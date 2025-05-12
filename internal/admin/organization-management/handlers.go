package organization_management

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewOrganizationHandler(store *PostgresStore) *OrganizationHandler {
	return &OrganizationHandler{Store: store}
}

// Helper to serialize details to string for audit logs
func auditDetails(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// getActorID extracts the user_id from fiber context or returns "system" if not present
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

func (o *Organization) Validate() error {
	if o.Name == "" {
		return errors.New("organization name must not be empty")
	}
	if len(o.Name) > 128 {
		return errors.New("organization name too long")
	}
	if o.OwnerID == "" {
		return errors.New("owner_id must not be empty")
	}
	return nil
}

func (h *OrganizationHandler) CreateOrganization(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "organization", "create")
		if err != nil {
			logger.LogError("RBAC error", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
		if !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Organization
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateOrganization: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateOrganization: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	org, err := h.OrganizationService.CreateOrganization(c.Context(), input)
	if err != nil {
		logger.LogError("CreateOrganization: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.OrgAuditLogger != nil {
		go h.OrgAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        org.ID,
			ActorID:   getActorID(c),
			Action:    "create_organization",
			TargetID:  org.ID,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(org)
}

func (h *OrganizationHandler) UpdateOrganization(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "organization", "update")
		if err != nil {
			logger.LogError("RBAC error", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
		if !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Organization
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateOrganization: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateOrganization: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateOrganization: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	org, err := h.OrganizationService.UpdateOrganization(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateOrganization: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.OrgAuditLogger != nil {
		go h.OrgAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        org.ID,
			ActorID:   getActorID(c),
			Action:    "update_organization",
			TargetID:  org.ID,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(org)
}

func (h *OrganizationHandler) DeleteOrganization(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "organization", "delete")
		if err != nil {
			logger.LogError("RBAC error", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
		if !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteOrganization: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.OrganizationService.DeleteOrganization(c.Context(), input.ID); err != nil {
		logger.LogError("DeleteOrganization: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.OrgAuditLogger != nil {
		go h.OrgAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_organization",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *OrganizationHandler) GetOrganization(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "organization", "get")
		if err != nil {
			logger.LogError("RBAC error", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
		if !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetOrganization: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	org, err := h.OrganizationService.GetOrganization(c.Context(), input.ID)
	if err != nil {
		logger.LogError("GetOrganization: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.OrgAuditLogger != nil {
		go h.OrgAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        org.ID,
			ActorID:   getActorID(c),
			Action:    "get_organization",
			TargetID:  org.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(org)
}

func (h *OrganizationHandler) ListOrganizations(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "organization", "list")
		if err != nil {
			logger.LogError("RBAC error", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
		if !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		OwnerID  string `json:"owner_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListOrganizations: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	orgs, err := h.OrganizationService.ListOrganizations(c.Context(), input.OwnerID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListOrganizations: failed", logger.ErrorField(err), logger.String("owner_id", input.OwnerID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.OrgAuditLogger != nil {
		go h.OrgAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_organizations",
			TargetID:  input.OwnerID,
			Details:   auditDetails(map[string]interface{}{"owner_id": input.OwnerID, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"organizations": orgs, "page": input.Page, "page_size": input.PageSize})
}

func (h *OrganizationHandler) GetSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "organization", "get")
		if err != nil {
			logger.LogError("RBAC error", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
		if !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		OrgID string `json:"org_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.OrgID == "" {
		logger.LogError("GetSettings: org_id required", logger.String("org_id", input.OrgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id required"})
	}
	settings, err := h.Store.GetSettings(c.Context(), input.OrgID)
	if err != nil {
		logger.LogError("GetSettings: failed", logger.ErrorField(err), logger.String("org_id", input.OrgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.OrgAuditLogger != nil {
		go h.OrgAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "get_settings",
			TargetID:  input.OrgID,
			Details:   auditDetails(map[string]interface{}{"org_id": input.OrgID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(settings)
}

func (h *OrganizationHandler) UpdateSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		permitted, err := h.RBACService.CheckPermission(c.Context(), getActorID(c), "organization", "update")
		if err != nil {
			logger.LogError("RBAC error", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
		if !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		OrgID    string                 `json:"org_id"`
		Settings map[string]interface{} `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.OrgID == "" || input.Settings == nil {
		logger.LogError("UpdateSettings: missing required fields", logger.String("org_id", input.OrgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id and settings required"})
	}
	if err := h.Store.UpdateSettings(c.Context(), input.OrgID, input.Settings); err != nil {
		logger.LogError("UpdateSettings: failed", logger.ErrorField(err), logger.String("org_id", input.OrgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.OrgAuditLogger != nil {
		go h.OrgAuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "update_settings",
			TargetID:  input.OrgID,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
	}
	// Optionally: test connection/feature if settings include credentials, return result
	return c.JSON(fiber.Map{"ok": true})
}
