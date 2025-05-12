package security_management

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewSecurityHandler(store *PostgresStore, ownerOAuthConfig OAuthConfig, ownerSAMLConfig SAMLConfig, jwtSecretName string, authTypeConfig AuthTypeConfig) *SecurityHandler {
	return &SecurityHandler{
		Store:            store,
		OwnerOAuthConfig: ownerOAuthConfig,
		OwnerSAMLConfig:  ownerSAMLConfig,
		AuthTypeConfig:   authTypeConfig,
	}
}

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

func getTenantID(c *fiber.Ctx) string {
	tid := c.Get("X-Tenant-ID")
	if tid != "" {
		return tid
	}
	if v := c.Query("tenant_id"); v != "" {
		return v
	}
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	_ = c.BodyParser(&body)
	if body.TenantID != "" {
		return body.TenantID
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

func (h *SecurityHandler) ListUserSecurityEvents(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("ListUserSecurityEvents: invalid input", logger.ErrorField(err), logger.String("tenant_id", getTenantID(c)))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required", "tenant_id": getTenantID(c)})
	}
	events, err := h.SecurityEventService.ListUserSecurityEvents(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("ListUserSecurityEvents: failed", logger.ErrorField(err), logger.String("user_id", input.UserID), logger.String("tenant_id", getTenantID(c)))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error(), "tenant_id": getTenantID(c)})
	}
	// After every successful operation, add audit logging as described above using h.SecurityAuditLogService.CreateSecurityAuditLog.
	details := events
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_security_events",
		TargetID:  input.UserID,
		Details:   marshalAuditDetails(map[string]interface{}{"events": details, "tenant_id": getTenantID(c)}),
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(events)
}

func (h *SecurityHandler) ListUserLoginHistory(c *fiber.Ctx) error {
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

func (h *SecurityHandler) EnableMFA(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.MFAEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "MFA disabled"})
	}
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

func (h *SecurityHandler) DisableMFA(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.MFAEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "MFA disabled"})
	}
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

func (h *SecurityHandler) ResetUserPassword(c *fiber.Ctx) error {
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

func (h *SecurityHandler) ListUserSessions(c *fiber.Ctx) error {
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
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_sessions",
		TargetID:  input.UserID,
		Details:   marshalAuditDetails(input),
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(sessions)
}

func (h *SecurityHandler) RevokeUserSession(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "session", "revoke")
		if err != nil || !permitted {
			logger.LogError("RevokeUserSession: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID))
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

func (h *SecurityHandler) ListSecurityAuditLogs(c *fiber.Ctx) error {
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

func (h *SecurityHandler) ListUserAPIKeys(c *fiber.Ctx) error {
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

func (h *SecurityHandler) CreateUserAPIKey(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "api_key", "create")
		if err != nil || !permitted {
			logger.LogError("CreateUserAPIKey: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID))
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

func (h *SecurityHandler) RevokeUserAPIKey(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "api_key", "revoke")
		if err != nil || !permitted {
			logger.LogError("RevokeUserAPIKey: permission denied", logger.ErrorField(err), logger.String("actor_id", actorID))
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

func (h *SecurityHandler) ListUserDevices(c *fiber.Ctx) error {
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
	go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
		ID:        uuid.NewString(),
		ActorID:   getActorID(c),
		Action:    "list_user_devices",
		TargetID:  input.UserID,
		Details:   marshalAuditDetails(input),
		CreatedAt: time.Now().UTC(),
	})
	return c.JSON(devices)
}

func (h *SecurityHandler) RevokeUserDevice(c *fiber.Ctx) error {
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

func (h *SecurityHandler) ListBreaches(c *fiber.Ctx) error {
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

func (h *SecurityHandler) ListSecurityPolicies(c *fiber.Ctx) error {
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

func (h *SecurityHandler) CreateSecurityPolicy(c *fiber.Ctx) error {
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

func (h *SecurityHandler) UpdateSecurityPolicy(c *fiber.Ctx) error {
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

func (h *SecurityHandler) DeleteSecurityPolicy(c *fiber.Ctx) error {
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

func (h *SecurityHandler) GetSecurityAnalytics(c *fiber.Ctx) error {
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

func (h *SecurityHandler) ListAnomalies(c *fiber.Ctx) error {
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

func (h *SecurityHandler) GetSelfServiceSecurity(c *fiber.Ctx) error {
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

func (h *SecurityHandler) GetNotificationConfig(c *fiber.Ctx) error {
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

func (h *SecurityHandler) UpdateNotificationConfig(c *fiber.Ctx) error {
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

func (h *SecurityHandler) SendTestNotification(c *fiber.Ctx) error {
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
	var channel NotificationChannel
	switch input.Channel {
	case "email":
		channel = NotificationChannel("smtp")
	case "sms":
		channel = NotificationChannel("twilio")
	case "chat":
		channel = NotificationChannel("slack")
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	err := h.Store.SendNotification(c.Context(), getTenantID(c), channel, input.Recipients, input.Event, input.Details, 3)
	if err != nil {
		logger.LogError("SendTestNotification: send failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Runtime Enable/Disable Handler ---

func (h *SecurityHandler) GetSecurityModuleConfig(c *fiber.Ctx) error {
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

func (h *SecurityHandler) SetSecurityModuleConfig(c *fiber.Ctx) error {
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

func (h *SecurityHandler) SetNotificationChannelEnabled(c *fiber.Ctx) error {
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
		logger.LogError("SetNotificationChannelEnabled: invalid channel", logger.String("channel", input.Channel))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Provider,
			ActorID:   getActorID(c),
			Action:    "set_notification_channel_enabled",
			TargetID:  input.Provider,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) GetNotificationChannelEnabled(c *fiber.Ctx) error {
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
		logger.LogError("GetNotificationChannelEnabled: invalid channel", logger.String("channel", input.Channel))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Provider,
			ActorID:   getActorID(c),
			Action:    "get_notification_channel_enabled",
			TargetID:  input.Provider,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"enabled": enabled})
}

func (h *SecurityHandler) SetProviderConfig(c *fiber.Ctx) error {
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
		logger.LogError("SetProviderConfig: invalid channel", logger.String("channel", input.Channel))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Provider,
			ActorID:   getActorID(c),
			Action:    "set_provider_config",
			TargetID:  input.Provider,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) GetProviderConfig(c *fiber.Ctx) error {
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
		logger.LogError("GetProviderConfig: invalid channel", logger.String("channel", input.Channel))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid channel"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Provider,
			ActorID:   getActorID(c),
			Action:    "get_provider_config",
			TargetID:  input.Provider,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(cfg)
}

// --- Security Event Webhook Handlers ---

func (h *SecurityHandler) CreateWebhook(c *fiber.Ctx) error {
	var input SecurityEventWebhook
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateWebhook: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.URL == "" || len(input.EventTypes) == 0 || input.Secret == "" {
		logger.LogError("CreateWebhook: missing required fields")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing required fields"})
	}
	w, err := h.SecurityEventWebhookService.CreateWebhook(c.Context(), input)
	if err != nil {
		logger.LogError("CreateWebhook: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        w.ID,
			ActorID:   getActorID(c),
			Action:    "create_security_webhook",
			TargetID:  w.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(w)
}

func (h *SecurityHandler) ListWebhooks(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("ListWebhooks: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	list, err := h.SecurityEventWebhookService.ListWebhooks(c.Context(), tenantID)
	if err != nil {
		logger.LogError("ListWebhooks: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        tenantID,
			ActorID:   getActorID(c),
			Action:    "list_security_webhooks",
			TargetID:  tenantID,
			Details:   marshalAuditDetails(tenantID),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(list)
}

func (h *SecurityHandler) DeleteWebhook(c *fiber.Ctx) error {
	id := c.Query("id")
	tenantID := c.Query("tenant_id")
	if id == "" || tenantID == "" {
		logger.LogError("DeleteWebhook: id and tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and tenant_id required"})
	}
	err := h.SecurityEventWebhookService.DeleteWebhook(c.Context(), id, tenantID)
	if err != nil {
		logger.LogError("DeleteWebhook: failed", logger.ErrorField(err), logger.String("id", id), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "delete_security_webhook",
			TargetID:  id,
			Details:   marshalAuditDetails(map[string]string{"tenant_id": tenantID}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) TriggerWebhook(c *fiber.Ctx) error {
	id := c.Query("id")
	tenantID := c.Query("tenant_id")
	eventType := c.Query("event_type")
	var payload map[string]interface{}
	_ = c.BodyParser(&payload)
	if id == "" || tenantID == "" || eventType == "" {
		logger.LogError("TriggerWebhook: id, tenant_id, and event_type required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id, tenant_id, and event_type required"})
	}
	err := h.SecurityEventWebhookService.TriggerWebhook(c.Context(), id, tenantID, eventType, payload)
	if err != nil {
		logger.LogError("TriggerWebhook: failed", logger.ErrorField(err), logger.String("id", id), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "trigger_security_webhook",
			TargetID:  id,
			Details:   marshalAuditDetails(map[string]interface{}{"event_type": eventType, "payload": payload}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusOK)
}

// --- Password Reset/Verification Token Handlers ---

func (h *SecurityHandler) RequestPasswordResetToken(c *fiber.Ctx) error {
	var input struct {
		UserID    string        `json:"user_id"`
		ExpiresIn time.Duration `json:"expires_in"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.ExpiresIn <= 0 {
		logger.LogError("RequestPasswordResetToken: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id and expires_in required"})
	}
	token, err := h.PasswordResetTokenService.CreateToken(c.Context(), input.UserID, input.ExpiresIn)
	if err != nil {
		logger.LogError("RequestPasswordResetToken: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        token.ID,
			ActorID:   getActorID(c),
			Action:    "request_password_reset_token",
			TargetID:  token.UserID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(token)
}

func (h *SecurityHandler) VerifyPasswordResetToken(c *fiber.Ctx) error {
	var input struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&input); err != nil || input.Token == "" {
		logger.LogError("VerifyPasswordResetToken: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token required"})
	}
	token, err := h.PasswordResetTokenService.VerifyToken(c.Context(), input.Token)
	if err != nil {
		logger.LogError("VerifyPasswordResetToken: failed", logger.ErrorField(err), logger.String("token", input.Token))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        token.ID,
			ActorID:   getActorID(c),
			Action:    "verify_password_reset_token",
			TargetID:  token.UserID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(token)
}

func (h *SecurityHandler) UsePasswordResetToken(c *fiber.Ctx) error {
	var input struct {
		Token   string `json:"token"`
		UserID  string `json:"user_id"`
		NewPass string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Token == "" || input.UserID == "" || input.NewPass == "" {
		logger.LogError("UsePasswordResetToken: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token, user_id, and new_password required"})
	}
	if err := h.PasswordResetTokenService.UseToken(c.Context(), input.Token); err != nil {
		logger.LogError("UsePasswordResetToken: failed to use token", logger.ErrorField(err), logger.String("token", input.Token))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if err := h.PasswordService.ResetUserPassword(c.Context(), input.UserID, input.NewPass); err != nil {
		logger.LogError("UsePasswordResetToken: failed to reset password", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Token,
			ActorID:   getActorID(c),
			Action:    "use_password_reset_token",
			TargetID:  input.UserID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Rate Limit Config Handlers ---

func (h *SecurityHandler) SetRateLimit(c *fiber.Ctx) error {
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

func (h *SecurityHandler) GetRateLimit(c *fiber.Ctx) error {
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

func (h *SecurityHandler) DeleteRateLimit(c *fiber.Ctx) error {
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

// --- Auth Endpoints ---

func (h *SecurityHandler) Login(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.PasswordEnabled {
		logger.LogError("Login: password auth disabled")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "password auth disabled"})
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" || input.Password == "" {
		logger.LogError("Login: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
	}
	user, err := h.PasswordService.AuthenticateUser(c.Context(), input.Email, input.Password)
	if err != nil {
		logger.LogError("Login: invalid credentials", logger.ErrorField(err), logger.String("email", input.Email))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	ip := c.IP()
	device := c.Get("User-Agent")
	sess, err := h.SessionService.CreateSession(c.Context(), user.ID, ip, device, 24*time.Hour)
	if err != nil {
		logger.LogError("Login: failed to create session", logger.ErrorField(err), logger.String("user_id", user.ID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create session"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        sess.ID,
			ActorID:   user.ID,
			Action:    "login",
			TargetID:  user.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"token": sess.ID, "expires_at": sess.ExpiresAt})
}

func (h *SecurityHandler) RefreshSession(c *fiber.Ctx) error {
	var input struct {
		SessionID string `json:"session_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.SessionID == "" {
		logger.LogError("RefreshSession: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "session_id required"})
	}
	sess, err := h.SessionService.RefreshSession(c.Context(), input.SessionID, 24*time.Hour)
	if err != nil {
		logger.LogError("RefreshSession: failed", logger.ErrorField(err), logger.String("session_id", input.SessionID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid session"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        sess.ID,
			ActorID:   getActorID(c),
			Action:    "refresh_session",
			TargetID:  sess.UserID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"token": sess.ID, "expires_at": sess.ExpiresAt})
}

func (h *SecurityHandler) Logout(c *fiber.Ctx) error {
	var input struct {
		SessionID string `json:"session_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.SessionID == "" {
		logger.LogError("Logout: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "session_id required"})
	}
	if err := h.SessionService.LogoutSession(c.Context(), input.SessionID); err != nil {
		logger.LogError("Logout: failed", logger.ErrorField(err), logger.String("session_id", input.SessionID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to logout"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.SessionID,
			ActorID:   getActorID(c),
			Action:    "logout",
			TargetID:  input.SessionID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *SecurityHandler) Register(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.PasswordEnabled {
		logger.LogError("Register: registration disabled")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "registration disabled"})
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" || input.Password == "" {
		logger.LogError("Register: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
	}
	user, err := h.PasswordService.RegisterUser(c.Context(), input.Email, input.Password)
	if err != nil {
		logger.LogError("Register: failed", logger.ErrorField(err), logger.String("email", input.Email))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        user.ID,
			ActorID:   user.ID,
			Action:    "register",
			TargetID:  user.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(user)
}

func (h *SecurityHandler) VerifyEmail(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
		Token  string `json:"token"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.Token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id and token required"})
	}
	if err := h.PasswordService.VerifyEmail(c.Context(), input.UserID, input.Token); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.UserID,
			ActorID:   input.UserID,
			Action:    "verify_email",
			TargetID:  input.UserID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) ResendVerification(c *fiber.Ctx) error {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" {
		logger.LogError("ResendVerification: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email required"})
	}
	if err := h.PasswordService.ResendVerification(c.Context(), input.Email); err != nil {
		logger.LogError("ResendVerification: failed", logger.ErrorField(err), logger.String("email", input.Email))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Email,
			ActorID:   getActorID(c),
			Action:    "resend_verification",
			TargetID:  input.Email,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) ChangePassword(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("ChangePassword: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var input struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil || input.OldPassword == "" || input.NewPassword == "" {
		logger.LogError("ChangePassword: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "old_password and new_password required"})
	}
	if err := h.PasswordService.ChangePassword(c.Context(), userID, input.OldPassword, input.NewPassword); err != nil {
		logger.LogError("ChangePassword: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        userID,
			ActorID:   userID,
			Action:    "change_password",
			TargetID:  userID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) GetProfile(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("GetProfile: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	profile, err := h.PasswordService.GetProfile(c.Context(), userID)
	if err != nil {
		logger.LogError("GetProfile: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        userID,
			ActorID:   userID,
			Action:    "get_profile",
			TargetID:  userID,
			Details:   marshalAuditDetails(userID),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(profile)
}

func (h *SecurityHandler) UpdateProfile(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("UpdateProfile: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateProfile: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	profile, err := h.PasswordService.UpdateProfile(c.Context(), userID, input)
	if err != nil {
		logger.LogError("UpdateProfile: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        userID,
			ActorID:   userID,
			Action:    "update_profile",
			TargetID:  userID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(profile)
}

func (h *SecurityHandler) DeleteAccount(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("DeleteAccount: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	if err := h.PasswordService.DeleteAccount(c.Context(), userID); err != nil {
		logger.LogError("DeleteAccount: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        userID,
			ActorID:   userID,
			Action:    "delete_account",
			TargetID:  userID,
			Details:   marshalAuditDetails(userID),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) Consent(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("Consent: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var input struct {
		Consent string `json:"consent"`
	}
	if err := c.BodyParser(&input); err != nil || input.Consent == "" {
		logger.LogError("Consent: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "consent required"})
	}
	if err := h.PasswordService.Consent(c.Context(), userID, input.Consent); err != nil {
		logger.LogError("Consent: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        userID,
			ActorID:   userID,
			Action:    "consent",
			TargetID:  userID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- MFA Challenge/Verify ---
func (h *SecurityHandler) MFAChallenge(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("MFAChallenge: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	challenge, err := h.MFAService.GenerateChallenge(c.Context(), userID)
	if err != nil {
		logger.LogError("MFAChallenge: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        userID,
			ActorID:   userID,
			Action:    "mfa_challenge",
			TargetID:  userID,
			Details:   marshalAuditDetails(userID),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(challenge)
}

func (h *SecurityHandler) MFAVerify(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("MFAVerify: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil || input.Code == "" {
		logger.LogError("MFAVerify: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code required"})
	}
	if err := h.MFAService.VerifyChallenge(c.Context(), userID, input.Code); err != nil {
		logger.LogError("MFAVerify: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid code"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        userID,
			ActorID:   userID,
			Action:    "mfa_verify",
			TargetID:  userID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Invite Send/Accept ---
func (h *SecurityHandler) SendInvite(c *fiber.Ctx) error {
	var input struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" || input.Role == "" {
		logger.LogError("SendInvite: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and role required"})
	}
	if err := h.PasswordService.SendInvite(c.Context(), input.Email, input.Role); err != nil {
		logger.LogError("SendInvite: failed", logger.ErrorField(err), logger.String("email", input.Email))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Email,
			ActorID:   getActorID(c),
			Action:    "send_invite",
			TargetID:  input.Email,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) AcceptInvite(c *fiber.Ctx) error {
	var input struct {
		Token    string `json:"token"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Token == "" || input.Email == "" || input.Password == "" {
		logger.LogError("AcceptInvite: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token, email, and password required"})
	}
	user, err := h.PasswordService.AcceptInvite(c.Context(), input.Token, input.Email, input.Password)
	if err != nil {
		logger.LogError("AcceptInvite: failed", logger.ErrorField(err), logger.String("email", input.Email))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        user.ID,
			ActorID:   user.ID,
			Action:    "accept_invite",
			TargetID:  user.ID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(user)
}

// --- Device Trust ---
func (h *SecurityHandler) TrustDevice(c *fiber.Ctx) error {
	userID := getActorID(c)
	if userID == "" {
		logger.LogError("TrustDevice: unauthorized", logger.String("user_id", userID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var input struct {
		DeviceID string `json:"device_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.DeviceID == "" {
		logger.LogError("TrustDevice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id required"})
	}
	if err := h.DeviceService.TrustDevice(c.Context(), userID, input.DeviceID); err != nil {
		logger.LogError("TrustDevice: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.DeviceID,
			ActorID:   userID,
			Action:    "trust_device",
			TargetID:  input.DeviceID,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Account Recovery ---
func (h *SecurityHandler) AccountRecover(c *fiber.Ctx) error {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" {
		logger.LogError("AccountRecover: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email required"})
	}
	if err := h.PasswordService.AccountRecover(c.Context(), input.Email); err != nil {
		logger.LogError("AccountRecover: failed", logger.ErrorField(err), logger.String("email", input.Email))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        input.Email,
			ActorID:   getActorID(c),
			Action:    "account_recover",
			TargetID:  input.Email,
			Details:   marshalAuditDetails(input),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func generateStateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (h *SecurityHandler) AuthGoogle(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.OAuthEnabled {
		logger.LogError("AuthGoogle: OAuth disabled")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "OAuth disabled"})
	}
	state := generateStateToken()
	c.Cookie(&fiber.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		Path:     "/",
	})
	params := url.Values{}
	params.Set("client_id", h.OwnerOAuthConfig.Google.ClientID)
	params.Set("redirect_uri", h.OwnerOAuthConfig.Google.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(h.OwnerOAuthConfig.Google.Scopes, " "))
	params.Set("state", state)
	oauthURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        generateStateToken(),
			ActorID:   getActorID(c),
			Action:    "auth_google_redirect",
			TargetID:  "",
			Details:   marshalAuditDetails(params),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Redirect(oauthURL, http.StatusFound)
}

func (h *SecurityHandler) AuthGoogleCallback(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.OAuthEnabled {
		logger.LogError("AuthGoogleCallback: OAuth disabled")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "OAuth disabled"})
	}
	state := c.Query("state")
	code := c.Query("code")
	cookieState := c.Cookies("oauth_state")
	if state == "" || code == "" || state != cookieState {
		logger.LogError("AuthGoogleCallback: invalid state or code", logger.String("state", state))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid state or code"})
	}
	// Exchange code for token
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {h.OwnerOAuthConfig.Google.ClientID},
		"client_secret": {h.OwnerOAuthConfig.Google.ClientSecret},
		"redirect_uri":  {h.OwnerOAuthConfig.Google.RedirectURI},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		logger.LogError("AuthGoogleCallback: token exchange failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "token exchange failed"})
	}
	defer tokenResp.Body.Close()
	body, _ := ioutil.ReadAll(tokenResp.Body)
	var tokenData struct {
		AccessToken string `json:"access_token"`
		IdToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenData); err != nil || tokenData.AccessToken == "" {
		logger.LogError("AuthGoogleCallback: invalid token response", logger.ErrorField(err))
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "invalid token response"})
	}
	// Fetch user info
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.LogError("AuthGoogleCallback: userinfo fetch failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "userinfo fetch failed"})
	}
	defer resp.Body.Close()
	userBody, _ := ioutil.ReadAll(resp.Body)
	var userInfo struct {
		Email string `json:"email"`
		Id    string `json:"id"`
	}
	if err := json.Unmarshal(userBody, &userInfo); err != nil || userInfo.Email == "" {
		logger.LogError("AuthGoogleCallback: invalid userinfo", logger.ErrorField(err))
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "invalid userinfo"})
	}
	// Find or create user
	user, err := h.PasswordService.RegisterUser(c.Context(), userInfo.Email, "")
	if err != nil && !strings.Contains(err.Error(), "duplicate") {
		logger.LogError("AuthGoogleCallback: user create failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user create failed"})
	}
	if err != nil && strings.Contains(err.Error(), "duplicate") {
		user, err = h.PasswordService.AuthenticateUser(c.Context(), userInfo.Email, "")
		if err != nil {
			logger.LogError("AuthGoogleCallback: user lookup failed", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user lookup failed"})
		}
	}
	ip := c.IP()
	device := c.Get("User-Agent")
	sess, err := h.SessionService.CreateSession(c.Context(), user.ID, ip, device, 24*time.Hour)
	if err != nil {
		logger.LogError("AuthGoogleCallback: session create failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "session create failed"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        sess.ID,
			ActorID:   user.ID,
			Action:    "auth_google_callback",
			TargetID:  user.ID,
			Details:   marshalAuditDetails(userInfo),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"token": sess.ID, "expires_at": sess.ExpiresAt})
}

// SAML SSO (minimal, robust, but assumes SAML config is correct and SAMLResponse is valid)
func (h *SecurityHandler) AuthSAML(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.SAMLEnabled {
		logger.LogError("AuthSAML: SAML disabled")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "SAML disabled"})
	}
	samlRequest := base64.StdEncoding.EncodeToString([]byte("<SAMLRequest>")) // Replace with real SAMLRequest builder
	relayState := generateStateToken()
	c.Cookie(&fiber.Cookie{
		Name:     "saml_relay_state",
		Value:    relayState,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		Path:     "/",
	})
	idpURL := h.OwnerSAMLConfig.MetadataURL
	params := url.Values{}
	params.Set("SAMLRequest", samlRequest)
	params.Set("RelayState", relayState)
	samlURL := idpURL + "?" + params.Encode()
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        generateStateToken(),
			ActorID:   getActorID(c),
			Action:    "auth_saml_redirect",
			TargetID:  "",
			Details:   marshalAuditDetails(params),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.Redirect(samlURL, http.StatusFound)
}

func (h *SecurityHandler) AuthSAMLCallback(c *fiber.Ctx) error {
	if !h.AuthTypeConfig.SAMLEnabled {
		logger.LogError("AuthSAMLCallback: SAML disabled")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "SAML disabled"})
	}
	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")
	cookieRelay := c.Cookies("saml_relay_state")
	if samlResponse == "" || relayState == "" || relayState != cookieRelay {
		logger.LogError("AuthSAMLCallback: invalid relay state or SAMLResponse")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid relay state or SAMLResponse"})
	}
	// Parse SAMLResponse (in real code, use a SAML library)
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		logger.LogError("AuthSAMLCallback: decode failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid SAMLResponse"})
	}
	// Extract email from decoded SAMLResponse (stub: look for <Email> tag)
	email := ""
	if idx := strings.Index(string(decoded), "<Email>"); idx != -1 {
		end := strings.Index(string(decoded)[idx:], "</Email>")
		if end != -1 {
			email = string(decoded)[idx+len("<Email>") : idx+end]
		}
	}
	if email == "" {
		logger.LogError("AuthSAMLCallback: email not found in SAMLResponse")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email not found in SAMLResponse"})
	}
	// Find or create user
	user, err := h.PasswordService.RegisterUser(c.Context(), email, "")
	if err != nil && !strings.Contains(err.Error(), "duplicate") {
		logger.LogError("AuthSAMLCallback: user create failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user create failed"})
	}
	if err != nil && strings.Contains(err.Error(), "duplicate") {
		user, err = h.PasswordService.AuthenticateUser(c.Context(), email, "")
		if err != nil {
			logger.LogError("AuthSAMLCallback: user lookup failed", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user lookup failed"})
		}
	}
	ip := c.IP()
	device := c.Get("User-Agent")
	sess, err := h.SessionService.CreateSession(c.Context(), user.ID, ip, device, 24*time.Hour)
	if err != nil {
		logger.LogError("AuthSAMLCallback: session create failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "session create failed"})
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        sess.ID,
			ActorID:   user.ID,
			Action:    "auth_saml_callback",
			TargetID:  user.ID,
			Details:   marshalAuditDetails(email),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"token": sess.ID, "expires_at": sess.ExpiresAt})
}

// --- Runtime AuthTypeConfig Setter/Getters ---
func (h *SecurityHandler) SetAuthTypeConfig(cfg AuthTypeConfig) { h.AuthTypeConfig = cfg }
func (h *SecurityHandler) GetAuthTypeConfig() AuthTypeConfig    { return h.AuthTypeConfig }

func (h *SecurityHandler) GetNotificationProvidersStatus(c *fiber.Ctx) error {
	statuses := make(map[string]string)
	for name, provider := range providerRegistry {
		status, err := provider.Status(c.Context())
		if err != nil {
			statuses[name] = "error: " + err.Error()
		} else {
			statuses[name] = status
		}
	}
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        generateStateToken(),
			ActorID:   getActorID(c),
			Action:    "get_notification_providers_status",
			TargetID:  "",
			Details:   marshalAuditDetails(statuses),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(statuses)
}

func (h *SecurityHandler) RetryNotificationQueue(c *fiber.Ctx) error {
	if h.Store == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "store not configured"})
	}
	go h.Store.ProcessNotificationQueue(c.Context())
	if h.SecurityAuditLogService != nil {
		go h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:        generateStateToken(),
			ActorID:   getActorID(c),
			Action:    "retry_notification_queue",
			TargetID:  "",
			Details:   marshalAuditDetails("manual retry"),
			CreatedAt: time.Now().UTC(),
		})
	}
	return c.JSON(fiber.Map{"status": "retry triggered"})
}
