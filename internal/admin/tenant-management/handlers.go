package tenant_management

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

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

func marshalAuditDetails(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (t *Tenant) Validate() error {
	if t.Name == "" {
		return errors.New("tenant name must not be empty")
	}
	if len(t.Name) > 128 {
		return errors.New("tenant name too long")
	}
	return nil
}

func (h *TenantAdminHandler) CreateTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("CreateTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	var tenant Tenant
	if err := c.BodyParser(&tenant); err != nil {
		logger.LogError("CreateTenant: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := tenant.Validate(); err != nil {
		logger.LogError("CreateTenant: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if err := h.TenantStore.CreateTenant(c.Context(), &tenant); err != nil {
		logger.LogError("CreateTenant: failed", logger.ErrorField(err), logger.String("name", tenant.Name))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "create_tenant",
			TargetID:  tenant.ID,
			Details:   marshalAuditDetails(tenant),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(tenant)
}

func (h *TenantAdminHandler) UpdateTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("UpdateTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	var input struct {
		ID string `json:"id"`
		Tenant
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateTenant: id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	input.Tenant.ID = input.ID
	if err := input.Tenant.Validate(); err != nil {
		logger.LogError("UpdateTenant: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if err := h.TenantStore.UpdateTenant(c.Context(), &input.Tenant); err != nil {
		logger.LogError("UpdateTenant: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_tenant",
			TargetID:  input.ID,
			Details:   marshalAuditDetails(input.Tenant),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusOK).JSON(input.Tenant)
}

func (h *TenantAdminHandler) DeleteTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("DeleteTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteTenant: id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.TenantStore.DeleteTenant(c.Context(), input.ID); err != nil {
		logger.LogError("DeleteTenant: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "delete_tenant",
			TargetID:  input.ID,
			Details:   marshalAuditDetails(fiber.Map{"id": input.ID}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *TenantAdminHandler) GetTenant(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("GetTenant: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetTenant: id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	// ListTenants and filter (replace with GetTenantByID if needed)
	tenants, err := h.TenantStore.ListTenants(c.Context())
	if err != nil {
		logger.LogError("GetTenant: failed to list tenants", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch tenants"})
	}
	for _, t := range tenants {
		if tenant, ok := t.(Tenant); ok && tenant.ID == input.ID {
			if h.AuditLogger != nil {
				go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
					ID:        uuid.NewString(),
					ActorID:   getActorID(c),
					Action:    "read_tenant",
					TargetID:  input.ID,
					Details:   marshalAuditDetails(fiber.Map{"id": input.ID}),
					CreatedAt: time.Now().UTC(),
				})
			}
			return c.Status(fiber.StatusOK).JSON(tenant)
		}
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "read_tenant",
			TargetID:  input.ID,
			Details:   marshalAuditDetails(fiber.Map{"id": input.ID}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "tenant not found"})
}

func (h *TenantAdminHandler) ListTenants(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantStore == nil {
		logger.LogError("ListTenants: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "tenant store not configured"})
	}
	var filter TenantFilter
	if err := c.BodyParser(&filter); err != nil {
		logger.LogError("ListTenants: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	tenants, total, err := h.TenantStore.SearchTenants(c.Context(), filter)
	if err != nil {
		logger.LogError("ListTenants: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list tenants"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_tenants",
			TargetID:  "",
			Details:   marshalAuditDetails(filter),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"tenants": tenants, "total": total})
}

func (h *TenantAdminHandler) GetTenantSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_settings", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantSettingsStore == nil {
		logger.LogError("GetTenantSettings: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "settings store not configured"})
	}
	var tenantID string
	if err := c.BodyParser(&tenantID); err != nil {
		logger.LogError("GetTenantSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if tenantID == "" {
		logger.LogError("GetTenantSettings: id required", logger.String("id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	settings, err := h.TenantSettingsStore.GetTenantSettings(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetTenantSettings: failed", logger.ErrorField(err), logger.String("id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "read_tenant_settings",
			TargetID:  tenantID,
			Details:   marshalAuditDetails(fiber.Map{"id": tenantID}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

func (h *TenantAdminHandler) UpdateTenantSettings(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_settings", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	if h.TenantSettingsStore == nil {
		logger.LogError("UpdateTenantSettings: store not configured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "settings store not configured"})
	}
	type SettingsInput struct {
		TenantID string                 `json:"tenant_id"`
		Settings map[string]interface{} `json:"settings"`
	}
	var input SettingsInput
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateTenantSettings: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" {
		logger.LogError("UpdateTenantSettings: id required", logger.String("id", input.TenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	if err := validateTenantSettings(input.Settings); err != nil {
		logger.LogError("UpdateTenantSettings: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	settings, err := h.TenantSettingsStore.UpdateTenantSettings(c.Context(), input.TenantID, input.Settings)
	if err != nil {
		logger.LogError("UpdateTenantSettings: failed", logger.ErrorField(err), logger.String("id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_tenant_settings",
			TargetID:  input.TenantID,
			Details:   marshalAuditDetails(input.Settings),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

func validateTenantSettings(settings map[string]interface{}) error {
	// Add field-specific validation here
	if len(settings) == 0 {
		return errors.New("settings must not be empty")
	}
	return nil
}
