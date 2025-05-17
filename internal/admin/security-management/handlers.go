package security_management

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/auth"
	"github.com/subinc/subinc-backend/internal/pkg/auth/providers/jwt"
	"github.com/subinc/subinc-backend/internal/pkg/auth/providers/session"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewSecurityHandler(store *PostgresStore, auth *auth.AuthManager) *SecurityHandler {
	return &SecurityHandler{Store: store, Auth: auth}
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
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("ListUserSecurityEvents: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required", "tenant_id": getTenantID(c)})
	}

	// Optional pagination parameters
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 20)
	eventType := c.Query("event_type", "")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	events, err := h.SecurityEventService.ListUserSecurityEvents(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserSecurityEvents: failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("tenant_id", getTenantID(c)))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error(), "tenant_id": getTenantID(c)})
	}

	// Filter by event type if specified
	if eventType != "" {
		var filteredEvents []SecurityEvent
		for _, event := range events {
			if event.EventType == eventType {
				filteredEvents = append(filteredEvents, event)
			}
		}
		events = filteredEvents
	}

	// Calculate total before pagination
	total := len(events)

	// Apply pagination
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= len(events) {
		events = []SecurityEvent{}
	} else if end > len(events) {
		events = events[start:]
	} else {
		events = events[start:end]
	}

	return c.JSON(fiber.Map{
		"events":    events,
		"page":      page,
		"page_size": pageSize,
		"total":     total,
	})
}

func (h *SecurityHandler) GetUserSecurityEvent(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("GetUserSecurityEvent: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	eventID := c.Params("event_id")
	if eventID == "" {
		logger.LogError("GetUserSecurityEvent: missing event_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "event_id parameter required"})
	}

	events, err := h.SecurityEventService.ListUserSecurityEvents(c.Context(), userID)
	if err != nil {
		logger.LogError("GetUserSecurityEvent: failed to list events", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	// Find the specific event
	for _, event := range events {
		if event.ID == eventID {
			return c.JSON(event)
		}
	}

	logger.LogError("GetUserSecurityEvent: event not found", logger.String("user_id", userID), logger.String("event_id", eventID))
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "security event not found"})
}

func (h *SecurityHandler) ListUserLoginHistory(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("ListUserLoginHistory: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	// Optional pagination parameters
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 20)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	history, err := h.LoginHistoryService.ListUserLoginHistory(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserLoginHistory: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"history":   history,
		"page":      page,
		"page_size": pageSize,
		"total":     len(history),
	})
}

func (h *SecurityHandler) GetUserLoginHistoryItem(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("GetUserLoginHistoryItem: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	historyID := c.Params("history_id")
	if historyID == "" {
		logger.LogError("GetUserLoginHistoryItem: missing history_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "history_id parameter required"})
	}

	// Get all login history items
	history, err := h.LoginHistoryService.ListUserLoginHistory(c.Context(), userID)
	if err != nil {
		logger.LogError("GetUserLoginHistoryItem: failed to list history", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	// Find the specific history item
	for _, item := range history {
		if item.ID == historyID {
			return c.JSON(item)
		}
	}

	logger.LogError("GetUserLoginHistoryItem: history item not found", logger.String("user_id", userID), logger.String("history_id", historyID))
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "login history item not found"})
}

// --- MFA ---
// swagger:route PUT /users/{user_id}/mfa mfa enableMFA
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

	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("EnableMFA: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	if err := h.MFAService.EnableMFA(c.Context(), userID); err != nil {
		logger.LogError("EnableMFA: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:route DELETE /users/{user_id}/mfa mfa disableMFA
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

	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("DisableMFA: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	if err := h.MFAService.DisableMFA(c.Context(), userID); err != nil {
		logger.LogError("DisableMFA: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:route GET /users/{user_id}/mfa/challenge mfa mfaChallenge
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
	userID := c.Params("user_id")
	if userID == "" {
		userID = getActorID(c) // Fallback to actor ID if path param not available
	}

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

// swagger:route POST /users/{user_id}/mfa/verify mfa mfaVerify
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
	userID := c.Params("user_id")
	if userID == "" {
		userID = getActorID(c) // Fallback to actor ID if path param not available
	}

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
	return c.JSON(fiber.Map{
		"verified": true,
		"metadata": fiber.Map{
			"user_id": userID,
		},
	})
}

// swagger:parameters mfaVerify
// in: body
// name: body
// schema:
//   type: object
//   properties:
//     code:
//       type: string

// --- Sessions ---
// swagger:route POST /users/{user_id}/sessions sessions createUserSession
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
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("CreateUserSession: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	ip := c.IP()
	device := c.Get("User-Agent")

	var input struct {
		ExpiryHours int `json:"expiry_hours"`
	}
	if err := c.BodyParser(&input); err != nil {
		input.ExpiryHours = 24 // Default to 24 hours
	}

	durationHours := input.ExpiryHours
	if durationHours <= 0 {
		durationHours = 24
	}

	// Create session data map
	sessionData := map[string]interface{}{
		"ip":     ip,
		"device": device,
	}

	sess, err := h.SessionService.CreateSession(c.Context(), userID, "", sessionData)
	if err != nil {
		logger.LogError("CreateUserSession: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create session"})
	}

	return c.Status(fiber.StatusCreated).JSON(sess)
}

func (h *SecurityHandler) ListUserSessions(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("ListUserSessions: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	sessions, err := h.SessionService.ListUserSessions(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserSessions: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"sessions": sessions,
		"count":    len(sessions),
		"metadata": fiber.Map{
			"user_id": userID,
		},
	})
}

func (h *SecurityHandler) GetUserSession(c *fiber.Ctx) error {
	sessionID := c.Params("session_id")
	if sessionID == "" {
		logger.LogError("GetUserSession: missing session_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "session_id parameter required"})
	}

	sess, err := h.SessionService.GetSession(c.Context(), sessionID)
	if err != nil {
		logger.LogError("GetUserSession: failed", logger.ErrorField(err), logger.String("session_id", sessionID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}

	return c.JSON(sess)
}

func (h *SecurityHandler) DeleteUserSession(c *fiber.Ctx) error {
	sessionID := c.Params("session_id")
	if sessionID == "" {
		logger.LogError("DeleteUserSession: missing session_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "session_id parameter required"})
	}

	if err := h.SessionService.DeleteSession(c.Context(), sessionID); err != nil {
		logger.LogError("DeleteUserSession: failed", logger.ErrorField(err), logger.String("session_id", sessionID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete session"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) RevokeUserSession(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("RevokeUserSession: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	sessionID := c.Params("session_id")
	if sessionID == "" {
		logger.LogError("RevokeUserSession: missing session_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "session_id parameter required"})
	}

	if err := h.SessionService.RevokeUserSession(c.Context(), userID, sessionID); err != nil {
		logger.LogError("RevokeUserSession: failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("session_id", sessionID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) ListUserAPIKeys(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("ListUserAPIKeys: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	keys, err := h.APIKeyService.ListUserAPIKeys(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserAPIKeys: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"api_keys": keys,
		"count":    len(keys),
		"metadata": fiber.Map{
			"user_id": userID,
		},
	})
}

func (h *SecurityHandler) CreateUserAPIKey(c *fiber.Ctx) error {

	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("CreateUserAPIKey: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
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

func (h *SecurityHandler) RevokeUserAPIKey(c *fiber.Ctx) error {

	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("RevokeUserAPIKey: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	keyID := c.Params("key_id")
	if keyID == "" {
		logger.LogError("RevokeUserAPIKey: missing key_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "key_id parameter required"})
	}

	if err := h.APIKeyService.RevokeUserAPIKey(c.Context(), userID, keyID); err != nil {
		logger.LogError("RevokeUserAPIKey: failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("key_id", keyID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) ListUserDevices(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("ListUserDevices: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	devices, err := h.DeviceService.ListUserDevices(c.Context(), userID)
	if err != nil {
		logger.LogError("ListUserDevices: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"devices": devices,
		"count":   len(devices),
		"metadata": fiber.Map{
			"user_id": userID,
		},
	})
}

func (h *SecurityHandler) RevokeUserDevice(c *fiber.Ctx) error {

	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("RevokeUserDevice: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	deviceID := c.Params("device_id")
	if deviceID == "" {
		logger.LogError("RevokeUserDevice: missing device_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id parameter required"})
	}

	if err := h.DeviceService.RevokeUserDevice(c.Context(), userID, deviceID); err != nil {
		logger.LogError("RevokeUserDevice: failed", logger.ErrorField(err), logger.String("user_id", userID), logger.String("device_id", deviceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// --- Device Trust ---
func (h *SecurityHandler) TrustDevice(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		userID = getActorID(c) // Fallback to current user if path param not available
		if userID == "" {
			logger.LogError("TrustDevice: unauthorized", logger.String("user_id", userID))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
	}

	deviceID := c.Params("device_id")
	if deviceID == "" {
		logger.LogError("TrustDevice: missing device_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "device_id parameter required"})
	}

	if err := h.DeviceService.TrustDevice(c.Context(), userID, deviceID); err != nil {
		logger.LogError("TrustDevice: failed", logger.ErrorField(err), logger.String("user_id", userID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) ListBreaches(c *fiber.Ctx) error {
	// Permission check

	// Pagination parameters
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 20)

	// Filtering parameters
	breachType := c.Query("type", "")
	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	breaches, err := h.BreachService.ListBreaches(c.Context(), page, pageSize)
	if err != nil {
		logger.LogError("ListBreaches: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve breaches"})
	}

	// Apply filters if specified
	var filteredBreaches []Breach
	for _, breach := range breaches {
		// Skip if doesn't match type filter
		if breachType != "" && breach.Type != breachType {
			continue
		}

		// Date range filtering
		if startDate != "" {
			startTime, err := time.Parse(time.RFC3339, startDate)
			if err == nil && breach.DetectedAt.Before(startTime) {
				continue
			}
		}
		if endDate != "" {
			endTime, err := time.Parse(time.RFC3339, endDate)
			if err == nil && breach.DetectedAt.After(endTime) {
				continue
			}
		}

		filteredBreaches = append(filteredBreaches, breach)
	}

	return c.JSON(fiber.Map{
		"breaches":  filteredBreaches,
		"page":      page,
		"page_size": pageSize,
		"total":     len(filteredBreaches),
		"filters": fiber.Map{
			"type":       breachType,
			"start_date": startDate,
			"end_date":   endDate,
		},
	})
}

func (h *SecurityHandler) GetBreach(c *fiber.Ctx) error {

	breachID := c.Params("breach_id")
	if breachID == "" {
		logger.LogError("GetBreach: missing breach_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "breach_id parameter required"})
	}

	// Retrieve all breaches and search for the specified ID
	// In a production environment, this should be a direct database query by ID
	page := 1
	pageSize := 100
	var foundBreach *Breach

	for {
		breaches, err := h.BreachService.ListBreaches(c.Context(), page, pageSize)
		if err != nil {
			logger.LogError("GetBreach: failed to list breaches", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve breaches"})
		}

		if len(breaches) == 0 {
			break // No more breaches to check
		}

		for i := range breaches {
			if breaches[i].ID == breachID {
				foundBreach = &breaches[i]
				break
			}
		}

		if foundBreach != nil || len(breaches) < pageSize {
			break // Found the breach or reached the end
		}

		page++
	}

	if foundBreach == nil {
		logger.LogError("GetBreach: breach not found", logger.String("breach_id", breachID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "breach not found"})
	}

	return c.JSON(foundBreach)
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
	// Permission check

	var policy SecurityPolicy
	if err := c.BodyParser(&policy); err != nil {
		logger.LogError("CreateSecurityPolicy: invalid request body", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	// Validate required fields
	if policy.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "policy name is required"})
	}

	// Set creation time
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = policy.CreatedAt

	// Generate UUID if not provided
	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}

	createdPolicy, err := h.SecurityPolicyService.CreateSecurityPolicy(c.Context(), policy)
	if err != nil {
		logger.LogError("CreateSecurityPolicy: creation failed", logger.ErrorField(err), logger.Any("policy", policy))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create security policy"})
	}

	return c.Status(fiber.StatusCreated).JSON(createdPolicy)
}

func (h *SecurityHandler) UpdateSecurityPolicy(c *fiber.Ctx) error {

	policyID := c.Params("id")
	if policyID == "" {
		logger.LogError("UpdateSecurityPolicy: missing policy ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "policy ID is required"})
	}

	var policyUpdate SecurityPolicy
	if err := c.BodyParser(&policyUpdate); err != nil {
		logger.LogError("UpdateSecurityPolicy: invalid request body", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	// Ensure the ID in the URL matches the ID in the body, or set it if not provided
	policyUpdate.ID = policyID

	// Validate required fields
	if policyUpdate.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "policy name is required"})
	}

	// Set update time
	policyUpdate.UpdatedAt = time.Now()

	updatedPolicy, err := h.SecurityPolicyService.UpdateSecurityPolicy(c.Context(), policyUpdate)
	if err != nil {
		logger.LogError("UpdateSecurityPolicy: update failed", logger.ErrorField(err), logger.Any("policy", policyUpdate))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update security policy"})
	}

	return c.JSON(updatedPolicy)
}

func (h *SecurityHandler) DeleteSecurityPolicy(c *fiber.Ctx) error {

	policyID := c.Params("id")
	if policyID == "" {
		logger.LogError("DeleteSecurityPolicy: missing policy ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "policy ID is required"})
	}

	// Verify policy exists before deletion
	policies, err := h.SecurityPolicyService.ListSecurityPolicies(c.Context())
	if err != nil {
		logger.LogError("DeleteSecurityPolicy: failed to list policies", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to verify policy existence"})
	}

	var policyExists bool
	var policyName string
	for _, policy := range policies {
		if policy.ID == policyID {
			policyExists = true
			policyName = policy.Name
			break
		}
	}

	if !policyExists {
		logger.LogError("DeleteSecurityPolicy: policy not found", logger.String("policy_id", policyID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "security policy not found"})
	}

	err = h.SecurityPolicyService.DeleteSecurityPolicy(c.Context(), policyID)
	if err != nil {
		logger.LogError("DeleteSecurityPolicy: deletion failed", logger.ErrorField(err), logger.String("policy_id", policyID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete security policy"})
	}

	// Audit the deletion
	if h.SecurityAuditLogService != nil {
		_, _ = h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:         uuid.NewString(),
			UserID:     getActorID(c),
			Action:     "delete_security_policy",
			Resource:   "security_policy",
			ResourceID: policyID,
			IP:         c.IP(),
			UserAgent:  c.Get("User-Agent"),
			CreatedAt:  time.Now(),
			Metadata: map[string]interface{}{
				"policy_name": policyName,
			},
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// --- Security Analytics Handlers ---

func (h *SecurityHandler) GetSecurityAnalytics(c *fiber.Ctx) error {

	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		tenantID = getTenantID(c) // Fallback to header/query tenantID
	}

	if tenantID == "" {
		logger.LogError("GetSecurityAnalytics: tenant ID required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant ID is required"})
	}

	analytics, err := h.SecurityAnalyticsService.GetSecurityAnalytics(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetSecurityAnalytics: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve security analytics"})
	}

	return c.JSON(analytics)
}

func (h *SecurityHandler) ListAnomalies(c *fiber.Ctx) error {

	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		tenantID = getTenantID(c) // Fallback to header/query tenantID
	}

	if tenantID == "" {
		logger.LogError("ListAnomalies: tenant ID required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant ID is required"})
	}

	// Pagination parameters
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 20)

	// Filtering
	anomalyType := c.Query("type", "")
	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	anomalies, err := h.SecurityAnalyticsService.ListAnomalies(c.Context(), tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListAnomalies: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve anomalies"})
	}

	// Apply filters if specified
	var filteredAnomalies []Anomaly
	for _, anomaly := range anomalies {
		// Skip if doesn't match type filter
		if anomalyType != "" && anomaly.Type != anomalyType {
			continue
		}

		// Date range filtering
		if startDate != "" {
			startTime, err := time.Parse(time.RFC3339, startDate)
			if err == nil && anomaly.DetectedAt.Before(startTime) {
				continue
			}
		}
		if endDate != "" {
			endTime, err := time.Parse(time.RFC3339, endDate)
			if err == nil && anomaly.DetectedAt.After(endTime) {
				continue
			}
		}

		filteredAnomalies = append(filteredAnomalies, anomaly)
	}

	return c.JSON(fiber.Map{
		"anomalies": filteredAnomalies,
		"page":      page,
		"page_size": pageSize,
		"total":     len(filteredAnomalies),
		"filters": fiber.Map{
			"type":       anomalyType,
			"start_date": startDate,
			"end_date":   endDate,
		},
	})
}

func (h *SecurityHandler) GetAnomaly(c *fiber.Ctx) error {

	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		tenantID = getTenantID(c) // Fallback to header/query tenantID
	}

	if tenantID == "" {
		logger.LogError("GetAnomaly: tenant ID required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant ID is required"})
	}

	anomalyID := c.Params("anomaly_id")
	if anomalyID == "" {
		logger.LogError("GetAnomaly: anomaly ID required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "anomaly ID is required"})
	}

	// Get all anomalies and find the specific one
	page := 1
	pageSize := 100
	var foundAnomaly *Anomaly

	for {
		anomalies, err := h.SecurityAnalyticsService.ListAnomalies(c.Context(), tenantID, page, pageSize)
		if err != nil {
			logger.LogError("GetAnomaly: failed to list anomalies", logger.ErrorField(err), logger.String("tenant_id", tenantID))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve anomalies"})
		}

		if len(anomalies) == 0 {
			break // No more anomalies to check
		}

		for i := range anomalies {
			if anomalies[i].ID == anomalyID {
				foundAnomaly = &anomalies[i]
				break
			}
		}

		if foundAnomaly != nil || len(anomalies) < pageSize {
			break // Found the anomaly or reached the end
		}

		page++
	}

	if foundAnomaly == nil {
		logger.LogError("GetAnomaly: anomaly not found", logger.String("tenant_id", tenantID), logger.String("anomaly_id", anomalyID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "anomaly not found"})
	}

	return c.JSON(foundAnomaly)
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
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetNotificationConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	cfg, err := h.NotificationService.GetNotificationConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetNotificationConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) UpdateNotificationConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("UpdateNotificationConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	var input NotificationConfig
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateNotificationConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid notification config"})
	}

	// Ensure tenant ID in config matches path parameter
	input.TenantID = tenantID

	if err := h.NotificationService.UpdateNotificationConfig(c.Context(), tenantID, input); err != nil {
		logger.LogError("UpdateNotificationConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Runtime Notification Test Handler ---
func (h *SecurityHandler) SendTestNotification(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		tenantID = getTenantID(c) // Fallback to header or query
	}

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
	err := h.Store.SendNotification(c.Context(), tenantID, channel, input.Recipients, input.Event, input.Details, 3)
	if err != nil {
		logger.LogError("SendTestNotification: send failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- Runtime Enable/Disable Handler ---

func (h *SecurityHandler) GetSecurityModuleConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetSecurityModuleConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	cfg, err := h.SecurityModuleConfigService.GetSecurityModuleConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetSecurityModuleConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) SetSecurityModuleConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("SetSecurityModuleConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	var input struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetSecurityModuleConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "enabled field required"})
	}

	if err := h.SecurityModuleConfigService.SetSecurityModuleConfig(c.Context(), tenantID, input.Enabled); err != nil {
		logger.LogError("SetSecurityModuleConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true, "tenant_id": tenantID, "enabled": input.Enabled})
}

func (h *SecurityHandler) SetNotificationChannelEnabled(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	channel := c.Params("channel")
	provider := c.Params("provider")

	if tenantID == "" || channel == "" || provider == "" {
		logger.LogError("SetNotificationChannelEnabled: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "tenant_id, channel and provider parameters required",
		})
	}

	var input struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetNotificationChannelEnabled: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "enabled field required"})
	}

	config := NotificationChannelEnabledConfig{
		TenantID: tenantID,
		Channel:  channel,
		Provider: provider,
		Enabled:  input.Enabled,
	}

	err := h.Store.SetNotificationChannelEnabledConfig(c.Context(), config)
	if err != nil {
		logger.LogError("SetNotificationChannelEnabled: failed", logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("channel", channel),
			logger.String("provider", provider))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true, "enabled": input.Enabled})
}

func (h *SecurityHandler) GetNotificationChannelEnabled(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	channel := c.Params("channel")
	provider := c.Params("provider")

	if tenantID == "" || channel == "" || provider == "" {
		logger.LogError("GetNotificationChannelEnabled: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "tenant_id, channel and provider parameters required",
		})
	}

	cfg, err := h.Store.GetNotificationChannelEnabledConfig(c.Context(), tenantID, channel, provider)
	if err != nil {
		logger.LogError("GetNotificationChannelEnabled: failed", logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("channel", channel),
			logger.String("provider", provider))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"enabled": cfg.Enabled})
}

func (h *SecurityHandler) SetProviderConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	channel := c.Params("channel")
	provider := c.Params("provider")

	if tenantID == "" || provider == "" {
		logger.LogError("SetProviderConfig: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "tenant_id and provider parameters required",
		})
	}

	var rawConfig map[string]interface{}
	if err := c.BodyParser(&rawConfig); err != nil {
		logger.LogError("SetProviderConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid config data"})
	}

	// If channel not in path, see if it's in the config
	if channel == "" {
		if ch, ok := rawConfig["channel"].(string); ok {
			channel = ch
			delete(rawConfig, "channel")
		}

		if channel == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "channel required"})
		}
	}

	// Convert map[string]interface{} to map[string]string
	configData := make(map[string]string)
	for key, val := range rawConfig {
		if strVal, ok := val.(string); ok {
			configData[key] = strVal
		} else {
			// For non-string values, attempt to convert them to JSON strings
			if jsonVal, err := json.Marshal(val); err == nil {
				configData[key] = string(jsonVal)
			} else {
				// If JSON conversion fails, use string representation
				configData[key] = fmt.Sprintf("%v", val)
			}
		}
	}

	providerConfig := ProviderConfig{
		TenantID: tenantID,
		Channel:  channel,
		Provider: provider,
		Config:   configData,
	}

	err := h.Store.SetProviderConfig(c.Context(), providerConfig)
	if err != nil {
		logger.LogError("SetProviderConfig: failed", logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("provider", provider))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}

func (h *SecurityHandler) GetProviderConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	channel := c.Params("channel")
	provider := c.Params("provider")

	if tenantID == "" || channel == "" || provider == "" {
		logger.LogError("GetProviderConfig: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "tenant_id, channel, and provider parameters required",
		})
	}

	cfg, err := h.Store.GetProviderConfig(c.Context(), tenantID, channel, provider)
	if err != nil {
		logger.LogError("GetProviderConfig: failed", logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("channel", channel),
			logger.String("provider", provider))
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
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("ListWebhooks: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	list, err := h.SecurityEventWebhookService.ListWebhooks(c.Context(), tenantID)
	if err != nil {
		logger.LogError("ListWebhooks: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{
		"webhooks": list,
		"count":    len(list),
		"metadata": fiber.Map{
			"tenant_id": tenantID,
		},
	})
}

func (h *SecurityHandler) DeleteWebhook(c *fiber.Ctx) error {
	webhookID := c.Params("webhook_id")
	tenantID := c.Params("tenant_id")

	if webhookID == "" || tenantID == "" {
		logger.LogError("DeleteWebhook: webhook_id and tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "webhook_id and tenant_id required"})
	}

	err := h.SecurityEventWebhookService.DeleteWebhook(c.Context(), webhookID, tenantID)
	if err != nil {
		logger.LogError("DeleteWebhook: failed", logger.ErrorField(err), logger.String("webhook_id", webhookID), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) TriggerWebhook(c *fiber.Ctx) error {
	webhookID := c.Params("webhook_id")
	tenantID := c.Params("tenant_id")

	var input struct {
		EventType string                 `json:"event_type"`
		Payload   map[string]interface{} `json:"payload"`
	}

	if err := c.BodyParser(&input); err != nil || input.EventType == "" {
		logger.LogError("TriggerWebhook: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "event_type required"})
	}

	if webhookID == "" || tenantID == "" {
		logger.LogError("TriggerWebhook: webhook_id and tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "webhook_id and tenant_id required"})
	}

	err := h.SecurityEventWebhookService.TriggerWebhook(c.Context(), webhookID, tenantID, input.EventType, input.Payload)
	if err != nil {
		logger.LogError("TriggerWebhook: failed", logger.ErrorField(err), logger.String("webhook_id", webhookID), logger.String("tenant_id", tenantID))
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
	token := c.Params("token")
	if token == "" {
		var input struct {
			Token string `json:"token"`
		}
		if err := c.BodyParser(&input); err != nil || input.Token == "" {
			logger.LogError("VerifyPasswordResetToken: invalid input", logger.ErrorField(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token required"})
		}
		token = input.Token
	}

	valid, err := h.PasswordResetTokenService.VerifyToken(c.Context(), token)
	if err != nil {
		logger.LogError("VerifyPasswordResetToken: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"valid": valid})
}

func (h *SecurityHandler) UsePasswordResetToken(c *fiber.Ctx) error {
	token := c.Params("token")
	if token == "" {
		var tokenInput struct {
			Token string `json:"token"`
		}
		if err := c.BodyParser(&tokenInput); err != nil || tokenInput.Token == "" {
			logger.LogError("UsePasswordResetToken: invalid token input", logger.ErrorField(err))
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token required"})
		}
		token = tokenInput.Token
	}

	var input struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := c.BodyParser(&input); err != nil || input.Password == "" || input.Email == "" {
		logger.LogError("UsePasswordResetToken: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
	}

	if err := h.PasswordResetTokenService.UseToken(c.Context(), token, input.Email, input.Password); err != nil {
		logger.LogError("UsePasswordResetToken: failed", logger.ErrorField(err), logger.String("email", input.Email))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// --- Rate Limit Config Handlers ---

func (h *SecurityHandler) SetRateLimit(c *fiber.Ctx) error {
	scope := c.Params("scope")
	scopeID := c.Params("scope_id")

	if scope == "" || scopeID == "" {
		logger.LogError("SetRateLimit: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "scope and scope_id parameters required",
		})
	}

	var input struct {
		Limit         int `json:"limit"`
		WindowSeconds int `json:"window_seconds"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetRateLimit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	if input.Limit <= 0 || input.WindowSeconds <= 0 {
		logger.LogError("SetRateLimit: invalid limits", logger.Int("limit", input.Limit), logger.Int("window_seconds", input.WindowSeconds))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "limit and window_seconds must be positive"})
	}

	config := RateLimitConfig{
		Scope:         scope,
		ScopeID:       scopeID,
		Limit:         input.Limit,
		WindowSeconds: input.WindowSeconds,
	}

	cfg, err := h.RateLimitService.SetRateLimit(c.Context(), config)
	if err != nil {
		logger.LogError("SetRateLimit: failed", logger.ErrorField(err),
			logger.String("scope", scope), logger.String("scope_id", scopeID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

func (h *SecurityHandler) GetRateLimit(c *fiber.Ctx) error {
	scope := c.Params("scope")
	scopeID := c.Params("scope_id")

	if scope == "" || scopeID == "" {
		logger.LogError("GetRateLimit: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "scope and scope_id parameters required",
		})
	}

	cfg, err := h.RateLimitService.GetRateLimit(c.Context(), scope, scopeID)
	if err != nil {
		logger.LogError("GetRateLimit: failed", logger.ErrorField(err),
			logger.String("scope", scope), logger.String("scope_id", scopeID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

func (h *SecurityHandler) DeleteRateLimit(c *fiber.Ctx) error {
	rateLimitID := c.Params("rate_limit_id")

	if rateLimitID == "" {
		logger.LogError("DeleteRateLimit: missing rate_limit_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "rate_limit_id parameter required"})
	}

	if err := h.RateLimitService.DeleteRateLimit(c.Context(), rateLimitID); err != nil {
		logger.LogError("DeleteRateLimit: failed", logger.ErrorField(err), logger.String("rate_limit_id", rateLimitID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) GetRateLimitConfig(c *fiber.Ctx) error {
	scope := c.Params("scope")
	scopeID := c.Params("scope_id")

	if scope == "" || scopeID == "" {
		logger.LogError("GetRateLimitConfig: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "scope and scope_id parameters required",
		})
	}

	cfg, err := h.Store.GetRateLimit(c.Context(), scope, scopeID)
	if err != nil {
		logger.LogError("GetRateLimitConfig: failed", logger.ErrorField(err),
			logger.String("scope", scope), logger.String("scope_id", scopeID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) SetRateLimitConfig(c *fiber.Ctx) error {
	scope := c.Params("scope")
	scopeID := c.Params("scope_id")

	if scope == "" || scopeID == "" {
		logger.LogError("SetRateLimitConfig: missing parameters")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "scope and scope_id parameters required",
		})
	}

	var input struct {
		Limit         int `json:"limit"`
		WindowSeconds int `json:"window_seconds"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetRateLimitConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	config := RateLimitConfig{
		Scope:         scope,
		ScopeID:       scopeID,
		Limit:         input.Limit,
		WindowSeconds: input.WindowSeconds,
	}

	err := h.Store.SetRateLimitConfig(c.Context(), config)
	if err != nil {
		logger.LogError("SetRateLimitConfig: failed", logger.ErrorField(err),
			logger.String("scope", scope), logger.String("scope_id", scopeID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
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
	// Get tenant-specific auth configuration
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.PasswordEnabled {
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeConfiguration,
			"Password login disabled for this tenant",
			"AUTH_LOGIN_001",
			err,
		))
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" || input.Password == "" {
		logger.LogError("Login: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
	}

	// Use password service to validate credentials
	user, err := h.PasswordService.AuthenticateUser(c.Context(), input.Email, input.Password)
	if err != nil {
		logger.LogError("Login: invalid credentials", logger.ErrorField(err), logger.String("email", input.Email))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeAuthentication,
			"Invalid credentials",
			"AUTH_LOGIN_002",
			err,
		))
	}

	// Get IP and device info for logging/security
	ip := c.IP()
	device := c.Get("User-Agent")

	// Get user profile to retrieve roles and other data
	profile, err := h.PasswordService.GetProfile(c.Context(), user.ID)
	if err != nil {
		logger.LogError("Login: failed to get user profile", logger.ErrorField(err), logger.String("user_id", user.ID))
		// Continue anyway, we'll just use minimal user data
	}

	// Extract roles from profile if available
	var roles []string
	if profile != nil {
		if rolesData, ok := profile["roles"]; ok {
			if rolesList, ok := rolesData.([]string); ok {
				roles = rolesList
			}
		}
	}

	// Use auth manager to select appropriate auth provider
	var preferredProvider string
	if cfg.Primary != "" {
		preferredProvider = cfg.Primary
	} else {
		preferredProvider = "default"
	}

	authProvider, err := h.Auth.GetProvider(preferredProvider)
	if err != nil || authProvider == nil {
		// Fall back to default provider
		authProvider, err = h.Auth.GetDefaultProvider()
		if err != nil {
			logger.LogError("Login: no auth provider available", logger.ErrorField(err))
			return auth.ToFiberError(auth.NewAuthError(
				auth.ErrorTypeInternal,
				"Authentication service unavailable",
				"AUTH_LOGIN_003",
				err,
			))
		}
	}

	// Create standard session data
	sessionData := map[string]interface{}{
		"ip":            ip,
		"device":        device,
		"login_time":    time.Now().UTC(),
		"login_method":  "password",
		"tenant_id":     tenantID,
		"email":         user.Email,
		"user_status":   user.Status,
		"last_activity": time.Now().UTC(),
		"auth_provider": preferredProvider,
	}

	// Add security metadata
	sessionData["security_metadata"] = map[string]interface{}{
		"ip_address":    ip,
		"user_agent":    device,
		"login_time":    time.Now().UTC(),
		"login_method":  "password",
		"authenticated": true,
	}

	// Add profile data if available
	if profile != nil {
		for k, v := range profile {
			// Don't overwrite critical fields
			if k != "ip" && k != "device" && k != "login_time" && k != "login_method" &&
				k != "tenant_id" && k != "security_metadata" && k != "auth_provider" {
				sessionData[k] = v
			}
		}
	}

	// For session provider, create a new session
	if authProvider.Name() == "session" {
		// Check if we have a session provider with extended API
		if sessionProvider, ok := authProvider.(*session.SessionProvider); ok {
			result, err := sessionProvider.CreateSession(c.Context(), user.ID, tenantID, user.Email, roles, sessionData)
			if err != nil {
				logger.LogError("Login: failed to create session", logger.ErrorField(err), logger.String("user_id", user.ID))
				return auth.ToFiberError(auth.NewAuthError(
					auth.ErrorTypeInternal,
					"Failed to create session",
					"AUTH_LOGIN_004",
					err,
				))
			}

			return c.JSON(fiber.Map{
				"refresh_token": result.Token.Token,
				"expires_at":    result.Token.ExpiresAt,
				"session_token": result.Token.Token,
				"user_id":       user.ID,
			})
		}
	}

	// For JWT provider, create token pair
	if authProvider.Name() == "jwt" {
		// Check if we have a JWT provider with extended API
		if jwtProvider, ok := authProvider.(*jwt.JWTProvider); ok {
			// Generate token pair
			accessToken, refreshToken, err := jwtProvider.GenerateTokenPair(user.ID, tenantID, user.Email, roles, sessionData)
			if err != nil {
				logger.LogError("Login: failed to generate JWT tokens", logger.ErrorField(err), logger.String("user_id", user.ID))
				return auth.ToFiberError(auth.NewAuthError(
					auth.ErrorTypeInternal,
					"Failed to generate token",
					"AUTH_LOGIN_005",
					err,
				))
			}

			return c.JSON(fiber.Map{
				"access_token":  accessToken.Token,
				"refresh_token": refreshToken.Token,
				"expires_at":    accessToken.ExpiresAt,
				"token_type":    "Bearer",
				"user_id":       user.ID,
			})
		}
	}

	// Generic fallback using standard AuthProvider interface
	result, err := authProvider.Authenticate(c.Context(), map[string]interface{}{
		"user_id":    user.ID,
		"tenant_id":  tenantID,
		"email":      user.Email,
		"roles":      roles,
		"ip":         ip,
		"device":     device,
		"login_time": time.Now().UTC(),
		"status":     user.Status,
	})
	if err != nil {
		logger.LogError("Login: authentication failed", logger.ErrorField(err), logger.String("user_id", user.ID))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Authentication failed",
			"AUTH_LOGIN_006",
			err,
		))
	}

	return c.JSON(fiber.Map{
		"access_token":  result.Token.Token,
		"refresh_token": result.Token.RefreshToken,
		"expires_at":    result.Token.ExpiresAt,
		"token_type":    result.Token.TokenType,
		"user_id":       user.ID,
	})
}

// Register creates a new user account
func (h *SecurityHandler) Register(c *fiber.Ctx) error {
	// Get tenant-specific auth configuration
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.PasswordEnabled { // Check if password auth is enabled, which implies registration is allowed
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeConfiguration,
			"User registration is disabled for this tenant",
			"AUTH_REG_001",
			err,
		))
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := c.BodyParser(&input); err != nil || input.Email == "" || input.Password == "" {
		logger.LogError("Register: invalid input", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeValidation,
			"Email and password are required",
			"AUTH_REG_002",
			err,
		))
	}

	// Create the user account
	user, err := h.PasswordService.RegisterUser(c.Context(), input.Email, input.Password)
	if err != nil {
		// Check for duplicate email error
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "already exists") {
			logger.LogError("Register: duplicate email", logger.ErrorField(err), logger.String("email", input.Email))
			return auth.ToFiberError(auth.NewAuthError(
				auth.ErrorTypeValidation,
				"Email address is already registered",
				"AUTH_REG_003",
				err,
			))
		}

		logger.LogError("Register: failed to create user", logger.ErrorField(err), logger.String("email", input.Email))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Failed to create user account",
			"AUTH_REG_004",
			err,
		))
	}

	// Update user profile with name if provided
	if input.Name != "" {
		profile := map[string]interface{}{
			"name": input.Name,
		}

		_, err = h.PasswordService.UpdateProfile(c.Context(), user.ID, profile)
		if err != nil {
			logger.LogError("Register: failed to update profile",
				logger.ErrorField(err),
				logger.String("user_id", user.ID),
				logger.String("email", input.Email))
			// Continue since we already created the user successfully
		}
	}

	// Create security audit log
	h.createAuditLog(c, "user_registered", "user", user.ID, input.Email)

	// Return user info with verification status
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"user_id":   user.ID,
		"email":     user.Email,
		"verified":  false,
		"status":    user.Status,
		"tenant_id": tenantID,
	})
}

// Logout invalidates the user's current session or token
func (h *SecurityHandler) Logout(c *fiber.Ctx) error {
	// Get session token from various possible locations
	token := c.Get("Authorization")
	if token == "" {
		token = c.Cookies("session_id")
	}
	if token == "" {
		token = c.Query("token")
	}

	// If no token found, consider it already logged out
	if token == "" {
		return c.SendStatus(fiber.StatusNoContent)
	}

	// Clean up Bearer prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Get auth type for the tenant
	tenantID := getTenantID(c)
	cfg, err := h.Store.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("Logout: failed to get auth config", logger.ErrorField(err))
		// Continue anyway with default behavior
	}

	// Get appropriate provider
	var providerName string
	if err == nil && cfg.Primary != "" {
		providerName = cfg.Primary
	} else {
		providerName = "default"
	}

	// Try to revoke the token with the appropriate provider
	var revocationErr error
	if h.Auth != nil {
		// Try with specified provider first
		provider, err := h.Auth.GetProvider(providerName)
		if err == nil && provider != nil {
			revocationErr = provider.RevokeToken(c.Context(), token)
			if revocationErr == nil {
				logger.Default.Info("Logout: token revoked successfully",
					logger.String("provider", provider.Name()))
			}
		}

		// If that fails, try with session service directly
		if revocationErr != nil && h.SessionService != nil {
			// Treat the token as a session ID
			err = h.SessionService.DeleteSession(c.Context(), token)
			if err == nil {
				logger.Default.Info("Logout: session deleted successfully")
				revocationErr = nil
			}
		}
	}

	// Even if there was an error revoking the token, we still want to
	// clear client-side session data

	// Clear any session cookies
	c.ClearCookie("session_id")

	// Return success status
	return c.SendStatus(fiber.StatusNoContent)
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
	sessionID := c.Get("X-Session-ID", "")
	if sessionID == "" {
		sessionID = c.Cookies("session_id")
	}

	if sessionID == "" {
		logger.LogError("RefreshSession: missing session ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "session ID required"})
	}

	// Default to 24 hours or parse from request
	var duration time.Duration = 24 * time.Hour
	if durationStr := c.Query("duration"); durationStr != "" {
		if parsedDuration, err := time.ParseDuration(durationStr); err == nil && parsedDuration > 0 {
			duration = parsedDuration
		}
	}

	// Attempt to refresh the session
	session, err := h.SessionService.RefreshUserSession(c.Context(), sessionID, duration)
	if err != nil {
		logger.LogError("RefreshSession: failed", logger.ErrorField(err), logger.String("session_id", sessionID))
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired session"})
	}

	// Set cookie if the client supports cookies
	if c.Get("X-No-Cookies", "") != "true" {
		cookie := new(fiber.Cookie)
		cookie.Name = "session_id"
		cookie.Value = session.ID
		cookie.Expires = session.ExpiresAt
		cookie.HTTPOnly = true
		cookie.Secure = true
		cookie.SameSite = "Strict"
		c.Cookie(cookie)
	}

	return c.JSON(fiber.Map{
		"session_id":  session.ID,
		"user_id":     session.UserID,
		"expires_at":  session.ExpiresAt,
		"renewed_at":  session.LastAccessAt,
		"valid_until": session.ExpiresAt,
	})
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
	userID := c.Params("user_id")
	if userID == "" {
		userID = getActorID(c) // Fallback to the current user
	}

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
	userID := c.Params("user_id")
	if userID == "" {
		userID = getActorID(c) // Fallback to the current user
	}

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
	cfg, err := h.ConfigurationService.GetAuthTypeConfig(c.Context(), tenantID)
	if err != nil || !cfg.OAuthEnabled {
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeConfiguration,
			"OAuth authentication is disabled for this tenant",
			"AUTH_OAUTH_001",
			err,
		))
	}

	oauthCfg, err := h.ConfigurationService.GetOAuthConfig(c.Context(), tenantID)
	if err != nil {
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeConfiguration,
			"OAuth configuration not found",
			"AUTH_OAUTH_002",
			err,
		))
	}

	state := c.Query("state")
	code := c.Query("code")
	cookieState := c.Cookies("oauth_state")
	if state == "" || code == "" || state != cookieState {
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeValidation,
			"Invalid OAuth state or code",
			"AUTH_OAUTH_003",
			nil,
		))
	}

	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {oauthCfg.ClientID},
		"client_secret": {oauthCfg.ClientSecret},
		"redirect_uri":  {oauthCfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		logger.LogError("AuthGoogleCallback: token exchange failed", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Failed to exchange OAuth token",
			"AUTH_OAUTH_004",
			err,
		))
	}
	defer tokenResp.Body.Close()

	body, _ := ioutil.ReadAll(tokenResp.Body)
	var tokenData struct {
		AccessToken string `json:"access_token"`
		IdToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenData); err != nil || tokenData.AccessToken == "" {
		logger.LogError("AuthGoogleCallback: invalid token response", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Invalid OAuth token response",
			"AUTH_OAUTH_005",
			err,
		))
	}

	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.LogError("AuthGoogleCallback: userinfo fetch failed", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Failed to fetch user info from OAuth provider",
			"AUTH_OAUTH_006",
			err,
		))
	}
	defer resp.Body.Close()

	userBody, _ := ioutil.ReadAll(resp.Body)
	var userInfo struct {
		Email string `json:"email"`
		Id    string `json:"id"`
	}
	if err := json.Unmarshal(userBody, &userInfo); err != nil || userInfo.Email == "" {
		logger.LogError("AuthGoogleCallback: invalid userinfo", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Invalid user info from OAuth provider",
			"AUTH_OAUTH_007",
			err,
		))
	}

	// Find or create user
	user, err := h.PasswordService.RegisterUser(c.Context(), userInfo.Email, "")
	if err != nil && !strings.Contains(err.Error(), "duplicate") {
		logger.LogError("AuthGoogleCallback: user create failed", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Failed to create user",
			"AUTH_OAUTH_008",
			err,
		))
	}

	if err != nil && strings.Contains(err.Error(), "duplicate") {
		user, err = h.PasswordService.AuthenticateUser(c.Context(), userInfo.Email, "")
		if err != nil {
			logger.LogError("AuthGoogleCallback: user lookup failed", logger.ErrorField(err))
			return auth.ToFiberError(auth.NewAuthError(
				auth.ErrorTypeInternal,
				"Failed to authenticate existing user",
				"AUTH_OAUTH_009",
				err,
			))
		}
	}

	// Create session with proper metadata
	ip := c.IP()
	device := c.Get("User-Agent")
	sessionData := map[string]interface{}{
		"ip":        ip,
		"device":    device,
		"auth_type": "oauth_google",
	}

	sess, err := h.SessionService.CreateSession(c.Context(), user.ID, tenantID, sessionData)
	if err != nil {
		logger.LogError("AuthGoogleCallback: session create failed", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Failed to create session",
			"AUTH_OAUTH_010",
			err,
		))
	}

	return c.JSON(fiber.Map{
		"token":      sess.ID,
		"expires_at": sess.ExpiresAt,
	})
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
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeConfiguration,
			"SAML authentication is disabled for this tenant",
			"AUTH_SAML_001",
			err,
		))
	}

	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")
	cookieRelay := c.Cookies("saml_relay_state")
	if samlResponse == "" || relayState == "" || relayState != cookieRelay {
		logger.LogError("AuthSAMLCallback: invalid SAML response or relay state")
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeValidation,
			"Invalid relay state or SAML response",
			"AUTH_SAML_002",
			nil,
		))
	}

	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		logger.LogError("AuthSAMLCallback: failed to decode SAML response", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeValidation,
			"Invalid SAML response format",
			"AUTH_SAML_003",
			err,
		))
	}

	email := ""
	if idx := strings.Index(string(decoded), "<Email>"); idx != -1 {
		end := strings.Index(string(decoded)[idx:], "</Email>")
		if end != -1 {
			email = string(decoded)[idx+len("<Email>") : idx+end]
		}
	}

	if email == "" {
		logger.LogError("AuthSAMLCallback: no email found in SAML response")
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeValidation,
			"Email not found in SAML response",
			"AUTH_SAML_004",
			nil,
		))
	}

	user, err := h.PasswordService.RegisterUser(c.Context(), email, "")
	if err != nil && !strings.Contains(err.Error(), "duplicate") {
		logger.LogError("AuthSAMLCallback: user create failed", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Failed to create user",
			"AUTH_SAML_005",
			err,
		))
	}

	if err != nil && strings.Contains(err.Error(), "duplicate") {
		user, err = h.PasswordService.AuthenticateUser(c.Context(), email, "")
		if err != nil {
			logger.LogError("AuthSAMLCallback: user lookup failed", logger.ErrorField(err))
			return auth.ToFiberError(auth.NewAuthError(
				auth.ErrorTypeInternal,
				"Failed to authenticate existing user",
				"AUTH_SAML_006",
				err,
			))
		}
	}

	ip := c.IP()
	device := c.Get("User-Agent")
	sessionData := map[string]interface{}{
		"ip":        ip,
		"device":    device,
		"auth_type": "saml",
	}

	sess, err := h.SessionService.CreateSession(c.Context(), user.ID, tenantID, sessionData)
	if err != nil {
		logger.LogError("AuthSAMLCallback: session create failed", logger.ErrorField(err))
		return auth.ToFiberError(auth.NewAuthError(
			auth.ErrorTypeInternal,
			"Failed to create session",
			"AUTH_SAML_007",
			err,
		))
	}

	return c.JSON(fiber.Map{
		"token":      sess.ID,
		"expires_at": sess.ExpiresAt,
	})
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
	userID := c.Params("user_id")
	if userID == "" {
		logger.LogError("GetMFAConfig: missing user_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id parameter required"})
	}

	tenantID := getTenantID(c)

	// Get user-specific MFA status
	userMFAStatus, err := h.Store.GetUserMFAStatus(c.Context(), userID)
	if err != nil {
		logger.LogError("GetMFAConfig: failed to get user MFA status",
			logger.ErrorField(err),
			logger.String("user_id", userID))
		// Continue with default values
		userMFAStatus = UserMFAStatus{
			UserID:  userID,
			Enabled: false,
			Methods: []string{},
		}
	}

	// Get tenant-level MFA configuration
	cfg, err := h.Store.GetMFAConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetMFAConfig: failed to get tenant config",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		// Return a response with just the user status
		return c.JSON(fiber.Map{
			"enabled": userMFAStatus.Enabled,
			"methods": userMFAStatus.Methods,
			"user_id": userID,
			"metadata": fiber.Map{
				"tenant_id": tenantID,
			},
		})
	}

	return c.JSON(fiber.Map{
		"enabled":       userMFAStatus.Enabled,
		"methods":       userMFAStatus.Methods,
		"user_id":       userID,
		"tenant_config": cfg,
		"metadata": fiber.Map{
			"tenant_id":    tenantID,
			"last_updated": userMFAStatus.LastUpdated,
		},
	})
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
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetPasswordPolicyConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	cfg, err := h.Store.GetPasswordPolicyConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetPasswordPolicyConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) SetPasswordPolicyConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("SetPasswordPolicyConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	var input PasswordPolicyConfig
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetPasswordPolicyConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	// Ensure tenant ID matches path parameter
	input.TenantID = tenantID

	err := h.Store.SetPasswordPolicyConfig(c.Context(), tenantID, input)
	if err != nil {
		logger.LogError("SetPasswordPolicyConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{
		"success": true,
		"config":  input,
	})
}

// --- SessionConfig Handlers ---
func (h *SecurityHandler) GetSessionConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("GetSessionConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	cfg, err := h.Store.GetSessionConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetSessionConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(cfg)
}

func (h *SecurityHandler) SetSessionConfig(c *fiber.Ctx) error {
	tenantID := c.Params("tenant_id")
	if tenantID == "" {
		logger.LogError("SetSessionConfig: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id parameter required"})
	}

	var input SessionConfig
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetSessionConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	// Ensure tenant ID matches path parameter
	input.TenantID = tenantID

	err := h.Store.SetSessionConfig(c.Context(), tenantID, input)
	if err != nil {
		logger.LogError("SetSessionConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{
		"success": true,
		"config":  input,
	})
}

func (h *SecurityHandler) ListSecurityAuditLogs(c *fiber.Ctx) error {

	// Pagination parameters
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 20)

	// Filtering parameters
	actorID := c.Query("actor_id", "")
	action := c.Query("action", "")
	targetID := c.Query("target_id", "")

	// Date range filters
	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	logs, err := h.SecurityAuditLogService.ListSecurityAuditLogs(c.Context(), page, pageSize)
	if err != nil {
		logger.LogError("ListSecurityAuditLogs: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve audit logs"})
	}

	// Apply filters if specified
	var filteredLogs []SecurityAuditLog
	for _, log := range logs {
		// Skip if doesn't match actor filter
		if actorID != "" && log.ActorID != actorID {
			continue
		}
		// Skip if doesn't match action filter
		if action != "" && log.Action != action {
			continue
		}
		// Skip if doesn't match target filter
		if targetID != "" && log.TargetID != targetID {
			continue
		}

		// Date range filtering
		if startDate != "" {
			startTime, err := time.Parse(time.RFC3339, startDate)
			if err == nil && log.CreatedAt.Before(startTime) {
				continue
			}
		}
		if endDate != "" {
			endTime, err := time.Parse(time.RFC3339, endDate)
			if err == nil && log.CreatedAt.After(endTime) {
				continue
			}
		}

		filteredLogs = append(filteredLogs, log)
	}

	return c.JSON(fiber.Map{
		"logs":      filteredLogs,
		"page":      page,
		"page_size": pageSize,
		"total":     len(filteredLogs),
		"filters": fiber.Map{
			"actor_id":   actorID,
			"action":     action,
			"target_id":  targetID,
			"start_date": startDate,
			"end_date":   endDate,
		},
	})
}

// --- Owner Admin Bootstrap Endpoint ---
func (h *SecurityHandler) BootstrapOwnerAdmin(c *fiber.Ctx) error {
	// Check if any users exist first - if they do, this endpoint shouldn't work
	count, err := h.PasswordService.CountUsers(c.Context())
	if err != nil {
		logger.LogError("BootstrapOwnerAdmin: failed to count users", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Could not check existing users",
		})
	}

	if count > 0 {
		logger.LogError("BootstrapOwnerAdmin: users already exist", logger.Int("count", count))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Cannot bootstrap admin when users already exist",
		})
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("BootstrapOwnerAdmin: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid input format",
		})
	}

	// Validate inputs
	if input.Email == "" || input.Password == "" || input.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email, password and name are required",
		})
	}

	// Register the user
	user, err := h.PasswordService.RegisterUser(c.Context(), input.Email, input.Password)
	if err != nil {
		logger.LogError("BootstrapOwnerAdmin: registration failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Update profile with name
	_, err = h.PasswordService.UpdateProfile(c.Context(), user.ID, map[string]interface{}{
		"name": input.Name,
		"role": "owner",
	})

	if err != nil {
		logger.LogError("BootstrapOwnerAdmin: failed to update profile",
			logger.ErrorField(err),
			logger.String("user_id", user.ID))
		// Continue anyway since the user was created
	}

	// Auto-verify this user's email since it's the bootstrap admin
	err = h.PasswordService.VerifyEmail(c.Context(), user.ID, "bootstrap")
	if err != nil {
		logger.LogError("BootstrapOwnerAdmin: failed to verify email",
			logger.ErrorField(err),
			logger.String("user_id", user.ID))
		// Continue anyway since the user was created
	}

	// Create a security audit log
	if h.SecurityAuditLogService != nil {
		h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:         uuid.NewString(),
			UserID:     user.ID,
			Action:     "owner_bootstrap",
			Resource:   "user",
			ResourceID: user.ID,
			IP:         c.IP(),
			UserAgent:  c.Get("User-Agent"),
			CreatedAt:  time.Now(),
			Metadata: map[string]interface{}{
				"email": input.Email,
			},
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"user": user,
		"metadata": fiber.Map{
			"verified": true,
			"role":     "owner",
		},
	})
}

func (h *SecurityHandler) ResetUserPassword(c *fiber.Ctx) error {
	var input struct {
		UserID      string `json:"user_id"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" || input.NewPassword == "" {
		logger.LogError("ResetUserPassword: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id and new_password required"})
	}
	if err := h.PasswordService.ResetUserPassword(c.Context(), input.UserID, input.NewPassword); err != nil {
		logger.LogError("ResetUserPassword: failed", logger.ErrorField(err), logger.String("user_id", input.UserID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SecurityHandler) GetSecurityAuditLog(c *fiber.Ctx) error {

	logID := c.Params("log_id")
	if logID == "" {
		logger.LogError("GetSecurityAuditLog: missing log_id parameter")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "log_id parameter required"})
	}

	// Retrieve all logs and search for the specified ID
	// In a production environment, this should be a direct database query by ID
	page := 1
	pageSize := 100
	var foundLog *SecurityAuditLog

	for {
		logs, err := h.SecurityAuditLogService.ListSecurityAuditLogs(c.Context(), page, pageSize)
		if err != nil {
			logger.LogError("GetSecurityAuditLog: failed to list logs", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve audit logs"})
		}

		if len(logs) == 0 {
			break // No more logs to check
		}

		for i := range logs {
			if logs[i].ID == logID {
				foundLog = &logs[i]
				break
			}
		}

		if foundLog != nil || len(logs) < pageSize {
			break // Found the log or reached the end
		}

		page++
	}

	if foundLog == nil {
		logger.LogError("GetSecurityAuditLog: log not found", logger.String("log_id", logID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "audit log not found"})
	}

	return c.JSON(foundLog)
}

// Security audit log creation with proper field usage
func (h *SecurityHandler) createAuditLog(c *fiber.Ctx, action, resourceType, resourceID, details string) {
	if h.SecurityAuditLogService != nil {
		h.SecurityAuditLogService.CreateSecurityAuditLog(c.Context(), SecurityAuditLog{
			ID:         uuid.NewString(),
			UserID:     getActorID(c),
			Action:     action,
			Resource:   resourceType,
			ResourceID: resourceID,
			IP:         c.IP(),
			UserAgent:  c.Get("User-Agent"),
			CreatedAt:  time.Now(),
			Metadata: map[string]interface{}{
				"details": details,
			},
		})
	}
}
