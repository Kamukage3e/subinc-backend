package security_management

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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

func (h *SecurityAdminHandler) ListUserSecurityEvents(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("ListUserSecurityEvents: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	events, err := h.SecurityEventService.ListUserSecurityEvents(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("ListUserSecurityEvents: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := events
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_security_events",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(events)
}

func (h *SecurityAdminHandler) ListUserLoginHistory(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("ListUserLoginHistory: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	history, err := h.LoginHistoryService.ListUserLoginHistory(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("ListUserLoginHistory: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := history
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_login_history",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(history)
}

func (h *SecurityAdminHandler) EnableMFA(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("EnableMFA: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	if err := h.MFAService.EnableMFA(c.Context(), input.UserID); err != nil {
		logger.LogError("EnableMFA: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"user_id": input.UserID}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "enable_mfa",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) DisableMFA(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("DisableMFA: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	if err := h.MFAService.DisableMFA(c.Context(), input.UserID); err != nil {
		logger.LogError("DisableMFA: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"user_id": input.UserID}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "disable_mfa",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ResetUserPassword(c *fiber.Ctx) error {
	var input struct {
		UserID      string `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.NewPassword == "" {
		logger.LogError("ResetUserPassword: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and new_password required"})
	}
	if err := h.PasswordService.ResetUserPassword(c.Context(), input.UserID, input.NewPassword); err != nil {
		logger.LogError("ResetUserPassword: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"user_id": input.UserID, "new_password": input.NewPassword}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "reset_user_password",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListUserSessions(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("ListUserSessions: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	sessions, err := h.SessionService.ListUserSessions(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("ListUserSessions: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := sessions
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_sessions",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(sessions)
}

func (h *SecurityAdminHandler) RevokeUserSession(c *fiber.Ctx) error {
	var input struct {
		UserID    string `json:"user_id"`
		SessionID string `json:"session_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.SessionID == "" {
		logger.LogError("RevokeUserSession: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and session id required"})
	}
	if err := h.SessionService.RevokeUserSession(c.Context(), input.UserID, input.SessionID); err != nil {
		logger.LogError("RevokeUserSession: failed", logger.ErrorField(err), logger.String("user_id", input.UserID), logger.String("session_id", input.SessionID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"user_id": input.UserID, "session_id": input.SessionID}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "revoke_user_session",
		TargetID:  input.SessionID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListSecurityAuditLogs(c *fiber.Ctx) error {
	var input struct {
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil || input.Page <= 0 || input.PageSize <= 0 {
		logger.LogError("ListSecurityAuditLogs: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid page or page_size"})
	}
	logs, err := h.SecurityAuditLogService.ListSecurityAuditLogs(c.Context(), input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListSecurityAuditLogs: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"page": input.Page, "page_size": input.PageSize}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   "",
		Action:    "list_security_audit_logs",
		TargetID:  "",
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(fiber.Map{"audit_logs": logs, "page": input.Page, "page_size": input.PageSize})
}

func (h *SecurityAdminHandler) ListUserAPIKeys(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("ListUserAPIKeys: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	keys, err := h.APIKeyService.ListUserAPIKeys(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("ListUserAPIKeys: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := keys
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_api_keys",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(keys)
}

func (h *SecurityAdminHandler) CreateUserAPIKey(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
		Name   string `json:"name"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.Name == "" {
		logger.LogError("CreateUserAPIKey: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and name required"})
	}
	key, err := h.APIKeyService.CreateUserAPIKey(c.Context(), input.UserID, input.Name)
	if err != nil {
		logger.LogError("CreateUserAPIKey: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"user_id": input.UserID, "name": input.Name}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "create_user_api_key",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.Status(fiber.StatusCreated).JSON(key)
}

func (h *SecurityAdminHandler) RevokeUserAPIKey(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
		KeyID  string `json:"key_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.KeyID == "" {
		logger.LogError("RevokeUserAPIKey: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and key id required"})
	}
	if err := h.APIKeyService.RevokeUserAPIKey(c.Context(), input.UserID, input.KeyID); err != nil {
		logger.LogError("RevokeUserAPIKey: failed", logger.ErrorField(err), logger.String("user_id", input.UserID), logger.String("key_id", input.KeyID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"user_id": input.UserID, "key_id": input.KeyID}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "revoke_user_api_key",
		TargetID:  input.KeyID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListUserDevices(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("ListUserDevices: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	devices, err := h.DeviceService.ListUserDevices(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("ListUserDevices: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := devices
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_devices",
		TargetID:  input.UserID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(devices)
}

func (h *SecurityAdminHandler) RevokeUserDevice(c *fiber.Ctx) error {
	var input struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.DeviceID == "" {
		logger.LogError("RevokeUserDevice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and device id required"})
	}
	if err := h.DeviceService.RevokeUserDevice(c.Context(), input.UserID, input.DeviceID); err != nil {
		logger.LogError("RevokeUserDevice: failed", logger.ErrorField(err), logger.String("user_id", input.UserID), logger.String("device_id", input.DeviceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"user_id": input.UserID, "device_id": input.DeviceID}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "revoke_user_device",
		TargetID:  input.DeviceID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) ListBreaches(c *fiber.Ctx) error {
	var input struct {
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil || input.Page <= 0 || input.PageSize <= 0 {
		logger.LogError("ListBreaches: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid page or page_size"})
	}
	breaches, err := h.BreachService.ListBreaches(c.Context(), input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListBreaches: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"page": input.Page, "page_size": input.PageSize}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   "",
		Action:    "list_breaches",
		TargetID:  "",
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(fiber.Map{"breaches": breaches, "page": input.Page, "page_size": input.PageSize})
}

func (h *SecurityAdminHandler) ListSecurityPolicies(c *fiber.Ctx) error {
	policies, err := h.SecurityPolicyService.ListSecurityPolicies(c.Context())
	if err != nil {
		logger.LogError("ListSecurityPolicies: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := policies
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   "",
		Action:    "list_security_policies",
		TargetID:  "",
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
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
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := input
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   "",
		Action:    "create_security_policy",
		TargetID:  "",
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (h *SecurityAdminHandler) UpdateSecurityPolicy(c *fiber.Ctx) error {
	var input SecurityPolicy
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSecurityPolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	policy, err := h.SecurityPolicyService.UpdateSecurityPolicy(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateSecurityPolicy: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := input
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   "",
		Action:    "update_security_policy",
		TargetID:  input.ID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(policy)
}

func (h *SecurityAdminHandler) DeleteSecurityPolicy(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteSecurityPolicy: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SecurityPolicyService.DeleteSecurityPolicy(c.Context(), input.ID); err != nil {
		logger.LogError("DeleteSecurityPolicy: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := fiber.Map{"id": input.ID}
	detailsBytes, _ := json.Marshal(details)
	detailsStr := string(detailsBytes)
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   "",
		Action:    "delete_security_policy",
		TargetID:  input.ID,
		Details:   detailsStr,
		CreatedAt: time.Now().UTC(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}
