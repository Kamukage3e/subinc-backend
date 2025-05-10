package security_management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type SecurityAdminHandler struct {
	SecurityEventService    SecurityEventService
	LoginHistoryService     LoginHistoryService
	MFAService              MFAService
	PasswordService         PasswordService
	SessionService          SessionService
	SecurityAuditLogService SecurityAuditLogService
	APIKeyService           APIKeyService
	DeviceService           DeviceService
	BreachService           BreachService
	SecurityPolicyService   SecurityPolicyService
}

func (h *SecurityAdminHandler) ListUserSecurityEvents(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("ListUserSecurityEvents: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	events, err := h.SecurityEventService.ListUserSecurityEvents(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserSecurityEvents: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(events)
}

func (h *SecurityAdminHandler) ListUserLoginHistory(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("ListUserLoginHistory: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	history, err := h.LoginHistoryService.ListUserLoginHistory(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserLoginHistory: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(history)
}

func (h *SecurityAdminHandler) EnableMFA(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("EnableMFA: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	if err := h.MFAService.EnableMFA(c.Context(), userID); err != nil {
		logger.LogError("EnableMFA: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) DisableMFA(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("DisableMFA: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	if err := h.MFAService.DisableMFA(c.Context(), userID); err != nil {
		logger.LogError("DisableMFA: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ResetUserPassword(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("ResetUserPassword: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	var input struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil || input.NewPassword == "" {
		logger.LogError("ResetUserPassword: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "new_password required"})
	}
	if err := h.PasswordService.ResetUserPassword(c.Context(), userID, input.NewPassword); err != nil {
		logger.LogError("ResetUserPassword: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListUserSessions(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("ListUserSessions: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	sessions, err := h.SessionService.ListUserSessions(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserSessions: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(sessions)
}

func (h *SecurityAdminHandler) RevokeUserSession(c *fiber.Ctx) error {
	userID := c.Params("id")
	sessionID := c.Params("session_id")
	if userID == "" || sessionID == "" {
		logger.LogError("RevokeUserSession: user id and session id required", logger.String("user_id", userID), logger.String("session_id", sessionID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and session id required"})
	}
	if err := h.SessionService.RevokeUserSession(c.Context(), userID, sessionID); err != nil {
		logger.LogError("RevokeUserSession: failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("session_id", sessionID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListSecurityAuditLogs(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.SecurityAuditLogService.ListSecurityAuditLogs(c.Context(), page, pageSize)
	if err != nil {
		logger.LogError("ListSecurityAuditLogs: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *SecurityAdminHandler) ListUserAPIKeys(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("ListUserAPIKeys: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	keys, err := h.APIKeyService.ListUserAPIKeys(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserAPIKeys: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(keys)
}

func (h *SecurityAdminHandler) CreateUserAPIKey(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("CreateUserAPIKey: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	var input struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&input); err != nil || input.Name == "" {
		logger.LogError("CreateUserAPIKey: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name required"})
	}
	key, err := h.APIKeyService.CreateUserAPIKey(c.Context(), userID, input.Name)
	if err != nil {
		logger.LogError("CreateUserAPIKey: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(key)
}

func (h *SecurityAdminHandler) RevokeUserAPIKey(c *fiber.Ctx) error {
	userID := c.Params("id")
	keyID := c.Params("key_id")
	if userID == "" || keyID == "" {
		logger.LogError("RevokeUserAPIKey: user id and key id required", logger.String("user_id", userID), logger.String("key_id", keyID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and key id required"})
	}
	if err := h.APIKeyService.RevokeUserAPIKey(c.Context(), userID, keyID); err != nil {
		logger.LogError("RevokeUserAPIKey: failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("key_id", keyID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListUserDevices(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		logger.LogError("ListUserDevices: user id required", logger.String("user_id", userID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	devices, err := h.DeviceService.ListUserDevices(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserDevices: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(devices)
}

func (h *SecurityAdminHandler) RevokeUserDevice(c *fiber.Ctx) error {
	userID := c.Params("id")
	deviceID := c.Params("device_id")
	if userID == "" || deviceID == "" {
		logger.LogError("RevokeUserDevice: user id and device id required", logger.String("user_id", userID), logger.String("device_id", deviceID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and device id required"})
	}
	if err := h.DeviceService.RevokeUserDevice(c.Context(), userID, deviceID); err != nil {
		logger.LogError("RevokeUserDevice: failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("device_id", deviceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListBreaches(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	breaches, err := h.BreachService.ListBreaches(c.Context(), page, pageSize)
	if err != nil {
		logger.LogError("ListBreaches: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"breaches": breaches, "page": page, "page_size": pageSize})
}

func (h *SecurityAdminHandler) ListSecurityPolicies(c *fiber.Ctx) error {
	policies, err := h.SecurityPolicyService.ListSecurityPolicies(c.Context())
	if err != nil {
		logger.LogError("ListSecurityPolicies: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(policies)
}

func (h *SecurityAdminHandler) CreateSecurityPolicy(c *fiber.Ctx) error {
	var input SecurityPolicy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateSecurityPolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	policy, err := h.SecurityPolicyService.CreateSecurityPolicy(c.Context(), input)
	if err != nil {
		logger.LogError("CreateSecurityPolicy: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (h *SecurityAdminHandler) UpdateSecurityPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateSecurityPolicy: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input SecurityPolicy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSecurityPolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	policy, err := h.SecurityPolicyService.UpdateSecurityPolicy(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateSecurityPolicy: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(policy)
}

func (h *SecurityAdminHandler) DeleteSecurityPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteSecurityPolicy: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SecurityPolicyService.DeleteSecurityPolicy(c.Context(), id); err != nil {
		logger.LogError("DeleteSecurityPolicy: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
