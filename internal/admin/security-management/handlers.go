package security_management

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

var (
	emailEnabled = map[string]bool{"smtp": true, "sendgrid": true}
	smsEnabled   = map[string]bool{"twilio": true, "nexmo": true}
	chatEnabled  = map[string]bool{"slack": true, "teams": true}
	emailConfig  = map[string]map[string]string{}
	smsConfig    = map[string]map[string]string{}
	chatConfig   = map[string]map[string]string{}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "mfa", "enable")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "mfa", "disable")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "user_password", "reset")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "session", "revoke")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "api_key", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "api_key", "revoke")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "device", "revoke")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "security_policy", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "security_policy", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "security_policy", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

// --- Security Analytics Handlers ---

func (h *SecurityAdminHandler) GetSecurityAnalytics(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetSecurityAnalytics: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	analytics, err := h.SecurityAnalyticsService.GetSecurityAnalytics(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetSecurityAnalytics: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "get_security_analytics",
			TargetID:  input.TenantID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(analytics)
}

func (h *SecurityAdminHandler) ListAnomalies(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("ListAnomalies: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 50
	}
	anomalies, err := h.SecurityAnalyticsService.ListAnomalies(c.Context(), input.TenantID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListAnomalies: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "list_anomalies",
			TargetID:  input.TenantID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(anomalies)
}

// --- Self-Service Security Portal Handlers ---

func (h *SecurityAdminHandler) GetSelfServiceSecurity(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	// Aggregate user security info: sessions, devices, MFA, API keys, recent events
	sessions, _ := h.SessionService.ListUserSessions(c.Context(), userID)
	devices, _ := h.DeviceService.ListUserDevices(c.Context(), userID)
	apiKeys, _ := h.APIKeyService.ListUserAPIKeys(c.Context(), userID)
	events, _ := h.SecurityEventService.ListUserSecurityEvents(c.Context(), userID)
	mfaEnabled := false
	if h.MFAService != nil {
		if err := h.MFAService.EnableMFA(c.Context(), userID); err == nil {
			mfaEnabled = true
		}
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   userID,
			Action:    "get_self_service_security",
			TargetID:  userID,
			Details:   marshalAuditDetails(userID),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{
		"sessions":    sessions,
		"devices":     devices,
		"api_keys":    apiKeys,
		"events":      events,
		"mfa_enabled": mfaEnabled,
	})
}

// --- Notification/Alerting Handlers ---

func (h *SecurityAdminHandler) GetNotificationConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetNotificationConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	cfg, err := h.NotificationService.GetNotificationConfig(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetNotificationConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "get_notification_config",
			TargetID:  input.TenantID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(cfg)
}

func (h *SecurityAdminHandler) UpdateNotificationConfig(c *fiber.Ctx) error {
	var input NotificationConfig
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("UpdateNotificationConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	if err := h.NotificationService.UpdateNotificationConfig(c.Context(), input); err != nil {
		logger.LogError("UpdateNotificationConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "update_notification_config",
			TargetID:  input.TenantID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Runtime Notification Test Handler ---

func (h *SecurityAdminHandler) SendTestNotification(c *fiber.Ctx) error {
	var input struct {
		Channel    string                 `json:"channel"`
		Provider   string                 `json:"provider"`
		Recipients []string               `json:"recipients"`
		Event      string                 `json:"event"`
		Details    map[string]interface{} `json:"details"`
	}
	if err := c.BodyParser(&input); err != nil || input.Channel == "" || input.Provider == "" || len(input.Recipients) == 0 {
		logger.LogError("SendTestNotification: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "channel, provider, and recipients required"})
	}
	var sendErr error
	switch input.Channel {
	case "email":
		sendErr = sendEmailProvider(input.Provider, input.Recipients, input.Event, input.Details)
	case "sms":
		sendErr = sendSMSProvider(input.Provider, input.Recipients, input.Event, input.Details)
	case "chat":
		sendErr = sendChatProvider(input.Provider, input.Recipients, input.Event, input.Details)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	if sendErr != nil {
		logger.LogError("SendTestNotification: send failed", logger.ErrorField(sendErr))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": sendErr.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Runtime Enable/Disable Handler ---

func (h *SecurityAdminHandler) GetSecurityModuleConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetSecurityModuleConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	cfg, err := h.SecurityModuleConfigService.GetSecurityModuleConfig(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetSecurityModuleConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "get_security_module_config",
			TargetID:  input.TenantID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(cfg)
}

func (h *SecurityAdminHandler) SetSecurityModuleConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
		Enabled  bool   `json:"enabled"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("SetSecurityModuleConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	if err := h.SecurityModuleConfigService.SetSecurityModuleConfig(c.Context(), input.TenantID, input.Enabled); err != nil {
		logger.LogError("SetSecurityModuleConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        uuid.NewString(),
			ActorID:   getActorID(c),
			Action:    "set_security_module_config",
			TargetID:  input.TenantID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) SetNotificationChannelEnabled(c *fiber.Ctx) error {
	var input struct {
		Channel  string `json:"channel"`
		Provider string `json:"provider"`
		Enabled  bool   `json:"enabled"`
	}
	if err := c.BodyParser(&input); err != nil || input.Channel == "" || input.Provider == "" {
		logger.LogError("SetNotificationChannelEnabled: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "channel and provider required"})
	}
	switch input.Channel {
	case "email":
		emailEnabled[input.Provider] = input.Enabled
	case "sms":
		smsEnabled[input.Provider] = input.Enabled
	case "chat":
		chatEnabled[input.Provider] = input.Enabled
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) GetNotificationChannelEnabled(c *fiber.Ctx) error {
	var input struct {
		Channel  string `json:"channel"`
		Provider string `json:"provider"`
	}
	if err := c.BodyParser(&input); err != nil || input.Channel == "" || input.Provider == "" {
		logger.LogError("GetNotificationChannelEnabled: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "channel and provider required"})
	}
	var enabled bool
	switch input.Channel {
	case "email":
		enabled = emailEnabled[input.Provider]
	case "sms":
		enabled = smsEnabled[input.Provider]
	case "chat":
		enabled = chatEnabled[input.Provider]
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	return c.JSON(fiber.Map{"enabled": enabled})
}

func (h *SecurityAdminHandler) SetProviderConfig(c *fiber.Ctx) error {
	var input struct {
		Channel  string            `json:"channel"`
		Provider string            `json:"provider"`
		Config   map[string]string `json:"config"`
	}
	if err := c.BodyParser(&input); err != nil || input.Channel == "" || input.Provider == "" || input.Config == nil {
		logger.LogError("SetProviderConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "channel, provider, and config required"})
	}
	switch input.Channel {
	case "email":
		emailConfig[input.Provider] = input.Config
	case "sms":
		smsConfig[input.Provider] = input.Config
	case "chat":
		chatConfig[input.Provider] = input.Config
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) GetProviderConfig(c *fiber.Ctx) error {
	var input struct {
		Channel  string `json:"channel"`
		Provider string `json:"provider"`
	}
	if err := c.BodyParser(&input); err != nil || input.Channel == "" || input.Provider == "" {
		logger.LogError("GetProviderConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "channel and provider required"})
	}
	var cfg map[string]string
	switch input.Channel {
	case "email":
		cfg = emailConfig[input.Provider]
	case "sms":
		cfg = smsConfig[input.Provider]
	case "chat":
		cfg = chatConfig[input.Provider]
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	return c.JSON(cfg)
}

// --- Security Event Webhook Handlers ---

func (h *SecurityAdminHandler) CreateWebhook(c *fiber.Ctx) error {
	var input SecurityEventWebhook
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.URL == "" || len(input.EventTypes) == 0 || input.Secret == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing required fields"})
	}
	w, err := h.SecurityEventWebhookService.CreateWebhook(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		_, _ = h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        w.ID,
			ActorID:   c.Locals("actor_id").(string),
			Action:    "create_security_webhook",
			TargetID:  w.ID,
			Details:   toPrettyJSON(w),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(w)
}

func (h *SecurityAdminHandler) ListWebhooks(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	list, err := h.SecurityEventWebhookService.ListWebhooks(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(list)
}

func (h *SecurityAdminHandler) DeleteWebhook(c *fiber.Ctx) error {
	id := c.Query("id")
	tenantID := c.Query("tenant_id")
	if id == "" || tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and tenant_id required"})
	}
	err := h.SecurityEventWebhookService.DeleteWebhook(c.Context(), id, tenantID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		_, _ = h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        id,
			ActorID:   c.Locals("actor_id").(string),
			Action:    "delete_security_webhook",
			TargetID:  id,
			Details:   toPrettyJSON(map[string]string{"tenant_id": tenantID}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityAdminHandler) TriggerWebhook(c *fiber.Ctx) error {
	id := c.Query("id")
	tenantID := c.Query("tenant_id")
	eventType := c.Query("event_type")
	var payload map[string]interface{}
	_ = c.BodyParser(&payload)
	if id == "" || tenantID == "" || eventType == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id, tenant_id, and event_type required"})
	}
	err := h.SecurityEventWebhookService.TriggerWebhook(c.Context(), id, tenantID, eventType, payload)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		_, _ = h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        id,
			ActorID:   c.Locals("actor_id").(string),
			Action:    "trigger_security_webhook",
			TargetID:  id,
			Details:   toPrettyJSON(map[string]interface{}{"event_type": eventType, "payload": payload}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusOK)
}

// --- Password Reset/Verification Token Handlers ---

func (h *SecurityAdminHandler) RequestPasswordResetToken(c *fiber.Ctx) error {
	var input struct {
		UserID    string        `json:"user_id"`
		ExpiresIn time.Duration `json:"expires_in"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.ExpiresIn <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id and expires_in required"})
	}
	token, err := h.PasswordResetTokenService.CreateToken(c.Context(), input.UserID, input.ExpiresIn)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		_, _ = h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        token.ID,
			ActorID:   c.Locals("actor_id").(string),
			Action:    "request_password_reset_token",
			TargetID:  token.UserID,
			Details:   toPrettyJSON(token),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(token)
}

func (h *SecurityAdminHandler) VerifyPasswordResetToken(c *fiber.Ctx) error {
	var input struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&input); err != nil || input.Token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token required"})
	}
	token, err := h.PasswordResetTokenService.VerifyToken(c.Context(), input.Token)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(token)
}

func (h *SecurityAdminHandler) UsePasswordResetToken(c *fiber.Ctx) error {
	var input struct {
		Token   string `json:"token"`
		UserID  string `json:"user_id"`
		NewPass string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Token == "" || input.UserID == "" || input.NewPass == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token, user_id, and new_password required"})
	}
	if err := h.PasswordResetTokenService.UseToken(c.Context(), input.Token); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if err := h.PasswordService.ResetUserPassword(c.Context(), input.UserID, input.NewPass); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		_, _ = h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Token,
			ActorID:   c.Locals("actor_id").(string),
			Action:    "use_password_reset_token",
			TargetID:  input.UserID,
			Details:   toPrettyJSON(map[string]string{"token": input.Token, "user_id": input.UserID}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Rate Limit Config Handlers ---

func (h *SecurityAdminHandler) SetRateLimit(c *fiber.Ctx) error {
	var input RateLimitConfig
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	cfg, err := h.RateLimitService.SetRateLimit(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        cfg.ID,
			ActorID:   getActorID(c),
			Action:    "set_rate_limit",
			TargetID:  cfg.ScopeID,
			Details:   marshalAuditDetails(cfg),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

func (h *SecurityAdminHandler) GetRateLimit(c *fiber.Ctx) error {
	scope := c.Query("scope")
	scopeID := c.Query("scope_id")
	if scope == "" || scopeID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "scope and scope_id required"})
	}
	cfg, err := h.RateLimitService.GetRateLimit(c.Context(), scope, scopeID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        cfg.ID,
			ActorID:   getActorID(c),
			Action:    "get_rate_limit",
			TargetID:  cfg.ScopeID,
			Details:   marshalAuditDetails(cfg),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

func (h *SecurityAdminHandler) DeleteRateLimit(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RateLimitService.DeleteRateLimit(c.Context(), input.ID); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_rate_limit",
			TargetID:  input.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
