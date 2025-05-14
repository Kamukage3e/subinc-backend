package security_management

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewSecurityHandler(store *PostgresStore) *SecurityHandler {
	return &SecurityHandler{Store: store}
}

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
	return c.JSON(history)
}

// --- MFA ---
// swagger:route POST /users/mfa/enable mfa enableMFA
// summary: Enable MFA for user
// tags:
//   - mfa
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	204: SuccessResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *SecurityHandler) EnableMFA(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.MFAEnabled {
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
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:parameters enableMFA
// in: body
// name: body
// schema:
//   type: object
//   properties:
//     user_id:
//       type: string
//   required:
//     - user_id

// swagger:route POST /users/mfa/disable mfa disableMFA
// summary: Disable MFA for user
// tags:
//   - mfa
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	204: SuccessResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *SecurityHandler) DisableMFA(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.MFAEnabled {
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
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:parameters disableMFA
// in: body
// name: body
// schema:
//   type: object
//   properties:
//     user_id:
//       type: string
//   required:
//     - user_id

// swagger:route POST /users/mfa/challenge mfa mfaChallenge
// summary: Generate MFA challenge
// tags:
//   - mfa
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	200: MFAChallengeResponse
//	401: ErrorResponse
//	422: ErrorResponse
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
	return c.JSON(challenge)
}

// swagger:parameters mfaChallenge
// in: body
// name: body
// schema:
//   type: object
//   properties:
//     user_id:
//       type: string
//   required:
//     - user_id

// swagger:route POST /users/mfa/verify mfa mfaVerify
// summary: Verify MFA challenge
// tags:
//   - mfa
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	204: SuccessResponse
//	400: ErrorResponse
//	401: ErrorResponse
//	422: ErrorResponse
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
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:parameters mfaVerify
// in: body
// name: body
// schema:
//   type: object
//   properties:
//     code:
//       type: string
//   required:
//     - code

// --- Sessions ---
// swagger:route POST /users/sessions sessions createUserSession
// summary: Create user session
// tags:
//   - sessions
//
// responses:
//
//	201: SessionResponse
//	400: ErrorResponse
//	500: ErrorResponse
func (h *SecurityHandler) CreateUserSession(c *fiber.Ctx) error {
	var input struct {
		UserID   string `json:"user_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
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
	return c.JSON(fiber.Map{"breaches": breaches, "page": input.Page, "page_size": input.PageSize})
}

func (h *SecurityHandler) ListSecurityPolicies(c *fiber.Ctx) error {
	policies, err := h.SecurityPolicyService.ListSecurityPolicies(c.Context())
	if err != nil {
		logger.LogError("ListSecurityPolicies: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
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
	return c.JSON(cfg)
}

func (h *SecurityHandler) UpdateNotificationConfig(c *fiber.Ctx) error {
	var input NotificationConfig
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("UpdateNotificationConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	if err := h.NotificationService.UpdateNotificationConfig(c.Context(), input.TenantID, input); err != nil {
		logger.LogError("UpdateNotificationConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) SetNotificationChannelEnabled(c *fiber.Ctx) error {
	var input NotificationChannelEnabledConfig
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" || input.Channel == "" || input.Provider == "" {
		logger.LogError("SetNotificationChannelEnabled: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id, channel and provider required"})
	}
	err := h.Store.SetNotificationChannelEnabledConfig(c.Context(), input)
	if err != nil {
		logger.LogError("SetNotificationChannelEnabled: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *SecurityHandler) GetNotificationChannelEnabled(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
		Channel  string `json:"channel"`
		Provider string `json:"provider"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" || input.Channel == "" || input.Provider == "" {
		logger.LogError("GetNotificationChannelEnabled: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id, channel and provider required"})
	}
	cfg, err := h.Store.GetNotificationChannelEnabledConfig(c.Context(), input.TenantID, input.Channel, input.Provider)
	if err != nil {
		logger.LogError("GetNotificationChannelEnabled: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"enabled": cfg.Enabled})
}

func (h *SecurityHandler) SetProviderConfig(c *fiber.Ctx) error {
	var input ProviderConfig
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" || input.Channel == "" || input.Provider == "" || input.Config == nil {
		logger.LogError("SetProviderConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id, channel, provider, and config required"})
	}
	err := h.Store.SetProviderConfig(c.Context(), input)
	if err != nil {
		logger.LogError("SetProviderConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *SecurityHandler) GetProviderConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
		Channel  string `json:"channel"`
		Provider string `json:"provider"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" || input.Channel == "" || input.Provider == "" {
		logger.LogError("GetProviderConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id, channel, and provider required"})
	}
	cfg, err := h.Store.GetProviderConfig(c.Context(), input.TenantID, input.Channel, input.Provider)
	if err != nil {
		logger.LogError("GetProviderConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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

	// --- Send password reset notification (non-blocking) ---
	if h.NotificationService != nil {
		go func(token PasswordResetToken) {
			user, uerr := h.UserService.GetUser(c.Context(), token.UserID)
			if uerr != nil || user.Email == "" {
				logger.LogError("RequestPasswordResetToken: user not found for notification", logger.ErrorField(uerr), logger.String("user_id", token.UserID))
				return
			}
			details := map[string]interface{}{
				"user_id":    user.ID,
				"user_email": user.Email,
				"token_id":   token.ID,
				"token":      token.Token,
				"expires_at": token.ExpiresAt,
			}
			err := h.NotificationService.SendNotification(
				context.Background(),
				"", // tenantID not available on user
				NotificationEmail,
				[]string{user.Email},
				"password.reset_requested",
				details,
				3,
			)
			if err != nil {
				logger.LogError("RequestPasswordResetToken: notification failed", logger.ErrorField(err), logger.String("user_id", user.ID))
			}
		}(token)
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
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Auth Endpoints ---

// swagger:route POST /auth/login auth login
// ---
// summary: Login with email and password
// description: Authenticate user and return JWT token.
// tags:
//   - auth
//
// responses:
//
//	200: LoginResponse
//	400: ErrorResponse
//	401: ErrorResponse
func (h *SecurityHandler) Login(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.PasswordEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "password login disabled"})
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
	// --- JWT generation ---
	jwtSecretCfg, err := h.Store.GetOwnerJWTSecretConfig(c.Context())
	if err != nil {
		logger.LogError("Login: failed to get JWT secret config", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "JWT secret config unavailable"})
	}
	if jwtSecretCfg.SecretName == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "JWT secret config missing"})
	}
	claims := jwt.MapClaims{
		"user_id":   user.ID,
		"email":     user.Email,
		"tenant_id": tenantID,
		"exp":       time.Now().Add(24 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecretCfg.SecretName))
	if err != nil {
		logger.LogError("Login: failed to sign JWT", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to sign JWT"})
	}
	return c.JSON(fiber.Map{"refresh_token": sess.ID, "expires_at": sess.ExpiresAt, "session_token": tokenString})
}

// swagger:parameters login
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/LoginRequest'

// swagger:route POST /auth/logout auth logout
// ---
// summary: Logout and invalidate session
// description: Invalidate the current session token.
// tags:
//   - auth
//
// responses:
//
//	200: SuccessResponse
//	400: ErrorResponse
func (h *SecurityHandler) Logout(c *fiber.Ctx) error {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&input); err != nil || input.RefreshToken == "" {
		logger.LogError("Logout: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token required"})
	}
	if err := h.SessionService.LogoutSession(c.Context(), input.RefreshToken); err != nil {
		logger.LogError("Logout: failed", logger.ErrorField(err), logger.String("refresh_token", input.RefreshToken))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to logout"})
	}
	return c.JSON(fiber.Map{"success": true})
}

// swagger:parameters logout
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/LogoutRequest'

// swagger:route POST /auth/register auth register
// ---
// summary: Register a new user
// description: Register a new user with email and password.
// tags:
//   - auth
//
// responses:
//
//	201: RegisterResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *SecurityHandler) Register(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.PasswordEnabled {
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
	return c.Status(fiber.StatusCreated).JSON(user)
}

// swagger:parameters register
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/RegisterRequest'

// swagger:route POST /auth/verify-email auth verifyEmail
// ---
// summary: Verify user email
// description: Verify a user's email address with a token.
// tags:
//   - auth
//
// responses:
//
//	204: SuccessResponse
//	400: ErrorResponse
//	422: ErrorResponse
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
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:parameters verifyEmail
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/VerifyEmailRequest'

// swagger:route POST /auth/resend-verification auth resendVerification
// ---
// summary: Resend email verification
// description: Resend the email verification code.
// tags:
//   - auth
//
// responses:
//
//	204: SuccessResponse
//	400: ErrorResponse
//	422: ErrorResponse
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
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:parameters resendVerification
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/ResendVerificationRequest'

// swagger:route POST /auth/change-password auth changePassword
// ---
// summary: Change user password
// description: Change the password for the authenticated user.
// tags:
//   - auth
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	204: SuccessResponse
//	400: ErrorResponse
//	401: ErrorResponse
//	422: ErrorResponse
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
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:parameters changePassword
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/ChangePasswordRequest'

// swagger:route POST /auth/token/refresh auth refreshSession
// ---
// summary: Refresh session token
// description: Refresh the session token using a refresh token.
// tags:
//   - auth
//
// responses:
//
//	200: RefreshSessionResponse
//	400: ErrorResponse
//	401: ErrorResponse
func (h *SecurityHandler) RefreshSession(c *fiber.Ctx) error {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&input); err != nil || input.RefreshToken == "" {
		logger.LogError("RefreshSession: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token required"})
	}
	sess, err := h.SessionService.RefreshSession(c.Context(), input.RefreshToken, 24*time.Hour)
	if err != nil {
		logger.LogError("RefreshSession: failed", logger.ErrorField(err), logger.String("refresh_token", input.RefreshToken))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
	}
	return c.JSON(fiber.Map{"refresh_token": sess.ID, "expires_at": sess.ExpiresAt})
}

// swagger:parameters refreshSession
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/RefreshSessionRequest'

// swagger:route GET /users/profile users getProfile
// ---
// summary: Get user profile
// description: Get the profile of the authenticated user.
// tags:
//   - users
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	200: UserProfileResponse
//	401: ErrorResponse
//	404: ErrorResponse
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
	return c.JSON(profile)
}

// swagger:route PUT /users/profile users updateProfile
// ---
// summary: Update user profile
// description: Update the profile of the authenticated user.
// tags:
//   - users
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	200: UserProfileResponse
//	400: ErrorResponse
//	401: ErrorResponse
//	422: ErrorResponse
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
	return c.JSON(profile)
}

// swagger:parameters updateProfile
// in: body
// name: body
// schema:
//   type: object
//   additionalProperties: true

// swagger:route DELETE /users/profile users deleteAccount
// ---
// summary: Delete user account
// description: Delete the authenticated user's account.
// tags:
//   - users
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	204: SuccessResponse
//	401: ErrorResponse
//	422: ErrorResponse
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
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:parameters deleteAccount
// in: body
// name: body
// schema:
//   $ref: '#/components/schemas/DeleteAccountRequest'

// swagger:route POST /users/consent users consent
// ---
// summary: Record user consent
// description: Record consent for the authenticated user.
// tags:
//   - users
//
// security:
//   - bearerAuth: []
//
// responses:
//
//	204: SuccessResponse
//	400: ErrorResponse
//	401: ErrorResponse
//	422: ErrorResponse
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
	return c.SendStatus(fiber.StatusNoContent)
}

func generateStateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (h *SecurityHandler) AuthGoogle(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.OAuthEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "OAuth disabled"})
	}
	oauthCfg, err := h.Store.GetOAuthConfig(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "OAuth config not found"})
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
	params.Set("client_id", oauthCfg.ClientID)
	params.Set("redirect_uri", oauthCfg.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(oauthCfg.Scopes, " "))
	params.Set("state", state)
	oauthURL := "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
	return c.Redirect(oauthURL, http.StatusFound)
}

func (h *SecurityHandler) AuthGoogleCallback(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.OAuthEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "OAuth disabled"})
	}
	oauthCfg, err := h.Store.GetOAuthConfig(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "OAuth config not found"})
	}
	state := c.Query("state")
	code := c.Query("code")
	cookieState := c.Cookies("oauth_state")
	if state == "" || code == "" || state != cookieState {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid state or code"})
	}
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {oauthCfg.ClientID},
		"client_secret": {oauthCfg.ClientSecret},
		"redirect_uri":  {oauthCfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "token exchange failed"})
	}
	defer tokenResp.Body.Close()
	body, _ := ioutil.ReadAll(tokenResp.Body)
	var tokenData struct {
		AccessToken string `json:"access_token"`
		IdToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenData); err != nil || tokenData.AccessToken == "" {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "invalid token response"})
	}
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
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
	return c.JSON(fiber.Map{"token": sess.ID, "expires_at": sess.ExpiresAt})
}

// SAML SSO (minimal, robust, but assumes SAML config is correct and SAMLResponse is valid)
func (h *SecurityHandler) AuthSAML(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.SAMLEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "SAML disabled"})
	}
	samlCfg, err := h.Store.GetSAMLConfig(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "SAML config not found"})
	}
	samlRequest := base64.StdEncoding.EncodeToString([]byte("<SAMLRequest>"))
	relayState := generateStateToken()
	c.Cookie(&fiber.Cookie{
		Name:     "saml_relay_state",
		Value:    relayState,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		Path:     "/",
	})
	params := url.Values{}
	params.Set("SAMLRequest", samlRequest)
	params.Set("RelayState", relayState)
	samlURL := samlCfg.MetadataURL + "?" + params.Encode()
	return c.Redirect(samlURL, http.StatusFound)
}

func (h *SecurityHandler) AuthSAMLCallback(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.SAMLEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "SAML disabled"})
	}
	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")
	cookieRelay := c.Cookies("saml_relay_state")
	if samlResponse == "" || relayState == "" || relayState != cookieRelay {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid relay state or SAMLResponse"})
	}
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid SAMLResponse"})
	}
	email := ""
	if idx := strings.Index(string(decoded), "<Email>"); idx != -1 {
		end := strings.Index(string(decoded)[idx:], "</Email>")
		if end != -1 {
			email = string(decoded)[idx+len("<Email>") : idx+end]
		}
	}
	if email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email not found in SAMLResponse"})
	}
	user, err := h.PasswordService.RegisterUser(c.Context(), email, "")
	if err != nil && !strings.Contains(err.Error(), "duplicate") {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user create failed"})
	}
	if err != nil && strings.Contains(err.Error(), "duplicate") {
		user, err = h.PasswordService.AuthenticateUser(c.Context(), email, "")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user lookup failed"})
		}
	}
	ip := c.IP()
	device := c.Get("User-Agent")
	sess, err := h.SessionService.CreateSession(c.Context(), user.ID, ip, device, 24*time.Hour)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "session create failed"})
	}
	return c.JSON(fiber.Map{"token": sess.ID, "expires_at": sess.ExpiresAt})
}

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
	return c.JSON(statuses)
}

func (h *SecurityHandler) RetryNotificationQueue(c *fiber.Ctx) error {
	if h.Store == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "store not configured"})
	}
	go h.Store.ProcessNotificationQueue(c.Context())
	return c.JSON(fiber.Map{"status": "retry triggered"})
}

// --- MFAConfig Handlers ---
func (h *SecurityHandler) GetMFAConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetMFAConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	cfg, err := h.Store.GetMFAConfig(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetMFAConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) SetMFAConfig(c *fiber.Ctx) error {
	var input MFAConfig
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("SetMFAConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	err := h.Store.SetMFAConfig(c.Context(), input.TenantID, input)
	if err != nil {
		logger.LogError("SetMFAConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

// --- PasswordPolicyConfig Handlers ---
func (h *SecurityHandler) GetPasswordPolicyConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetPasswordPolicyConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	cfg, err := h.Store.GetPasswordPolicyConfig(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetPasswordPolicyConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) SetPasswordPolicyConfig(c *fiber.Ctx) error {
	var input PasswordPolicyConfig
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("SetPasswordPolicyConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	err := h.Store.SetPasswordPolicyConfig(c.Context(), input.TenantID, input)
	if err != nil {
		logger.LogError("SetPasswordPolicyConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

// --- SessionConfig Handlers ---
func (h *SecurityHandler) GetSessionConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetSessionConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	cfg, err := h.Store.GetSessionConfig(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetSessionConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) SetSessionConfig(c *fiber.Ctx) error {
	var input SessionConfig
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("SetSessionConfig: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	err := h.Store.SetSessionConfig(c.Context(), input.TenantID, input)
	if err != nil {
		logger.LogError("SetSessionConfig: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

// --- RateLimitConfig Handlers ---
func (h *SecurityHandler) SetRateLimitConfig(c *fiber.Ctx) error {
	var input RateLimitConfig
	if err := c.BodyParser(&input); err != nil || input.Scope == "" || input.ScopeID == "" {
		logger.LogError("SetRateLimitConfig: scope and scope_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "scope and scope_id required"})
	}
	err := h.Store.SetRateLimitConfig(c.Context(), input)
	if err != nil {
		logger.LogError("SetRateLimitConfig: failed", logger.ErrorField(err), logger.String("scope", input.Scope), logger.String("scope_id", input.ScopeID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *SecurityHandler) GetRateLimitConfig(c *fiber.Ctx) error {
	var input struct {
		Scope   string `json:"scope"`
		ScopeID string `json:"scope_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.Scope == "" || input.ScopeID == "" {
		logger.LogError("GetRateLimitConfig: scope and scope_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "scope and scope_id required"})
	}
	cfg, err := h.Store.GetRateLimit(c.Context(), input.Scope, input.ScopeID)
	if err != nil {
		logger.LogError("GetRateLimitConfig: failed", logger.ErrorField(err), logger.String("scope", input.Scope), logger.String("scope_id", input.ScopeID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

// --- User Session CRUD Handlers (robust, prod-ready, Redis-backed) ---

func (h *SecurityHandler) CreateUserSession(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
		IP     string `json:"ip"`
		Device string `json:"device"`
		TTL    int64  `json:"ttl_seconds"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		logger.LogError("CreateUserSession: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id required"})
	}
	expiry := time.Duration(input.TTL) * time.Second
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}
	sess, err := h.SessionService.CreateSession(c.Context(), input.UserID, input.IP, input.Device, expiry)
	if err != nil {
		logger.LogError("CreateUserSession: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create session"})
	}
	return c.Status(fiber.StatusCreated).JSON(sess)
}

func (h *SecurityHandler) DeleteUserSession(c *fiber.Ctx) error {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&input); err != nil || input.RefreshToken == "" {
		logger.LogError("DeleteUserSession: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token required"})
	}
	if err := h.SessionService.LogoutSession(c.Context(), input.RefreshToken); err != nil {
		logger.LogError("DeleteUserSession: failed", logger.ErrorField(err), logger.String("refresh_token", input.RefreshToken))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete session"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) GetUserSession(c *fiber.Ctx) error {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&input); err != nil || input.RefreshToken == "" {
		logger.LogError("GetUserSession: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token required"})
	}
	sess, err := h.SessionService.GetSession(c.Context(), input.RefreshToken)
	if err != nil {
		logger.LogError("GetUserSession: failed", logger.ErrorField(err), logger.String("refresh_token", input.RefreshToken))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}
	return c.JSON(sess)
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
		UserID       string `json:"user_id"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.RefreshToken == "" {
		logger.LogError("RevokeUserSession: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id and refresh token required"})
	}
	if err := h.SessionService.RevokeUserSession(c.Context(), input.UserID, input.RefreshToken); err != nil {
		logger.LogError("RevokeUserSession: failed", logger.ErrorField(err), logger.String("user_id", input.UserID), logger.String("refresh_token", input.RefreshToken))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Owner Admin Bootstrap Endpoint ---
func (h *SecurityHandler) BootstrapOwnerAdmin(c *fiber.Ctx) error {
	// Only allow if no users exist
	count, err := h.PasswordService.CountUsers(c.Context())
	if err != nil {
		logger.LogError("BootstrapOwnerAdmin: failed to count users", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if count > 0 {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "owner admin already exists"})
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
	}
	user, err := h.PasswordService.RegisterUser(c.Context(), input.Email, input.Password)
	if err != nil {
		logger.LogError("BootstrapOwnerAdmin: failed to register", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(user)
}
