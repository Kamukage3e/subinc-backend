package organization_management

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewOrganizationHandler(store *PostgresStore) *OrganizationHandler {
	return &OrganizationHandler{
		Store:               store,
		OrganizationService: store,
		OrgSettingsService:  store,
		OrgAuditLogger:      store.AuditLogger,
		RateLimitService:    nil,
	}
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

	return c.Status(fiber.StatusCreated).JSON(org)
}

func (h *OrganizationHandler) UpdateOrganization(c *fiber.Ctx) error {

	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateOrganization: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input Organization
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateOrganization: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateOrganization: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	org, err := h.OrganizationService.UpdateOrganization(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateOrganization: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(org)
}

func (h *OrganizationHandler) DeleteOrganization(c *fiber.Ctx) error {

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

func (h *OrganizationHandler) GetOrganization(c *fiber.Ctx) error {

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

func (h *OrganizationHandler) ListOrganizations(c *fiber.Ctx) error {

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

func (h *OrganizationHandler) GetSettings(c *fiber.Ctx) error {

	orgID := c.Params("id")
	if orgID == "" {
		logger.LogError("GetSettings: org_id required", logger.String("org_id", orgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id required"})
	}
	settings, err := h.OrgSettingsService.GetSettings(c.Context(), orgID)
	if err != nil {
		logger.LogError("GetSettings: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(settings)
}

func (h *OrganizationHandler) UpdateSettings(c *fiber.Ctx) error {

	orgID := c.Params("id")
	if orgID == "" {
		logger.LogError("UpdateSettings: org_id required", logger.String("org_id", orgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "org_id required"})
	}
	var input struct {
		Settings map[string]interface{} `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Settings == nil {
		logger.LogError("UpdateSettings: missing required fields", logger.String("org_id", orgID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "settings required"})
	}
	if err := h.OrgSettingsService.UpdateSettings(c.Context(), orgID, input.Settings); err != nil {
		logger.LogError("UpdateSettings: failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"ok": true})
}
