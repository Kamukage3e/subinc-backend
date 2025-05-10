package user_management

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type Handler struct {
	Store *PostgresStore
}

func NewHandler(store *PostgresStore) *Handler {
	return &Handler{Store: store}
}

// --- User Handlers ---
func (h *Handler) CreateUser(c *fiber.Ctx) error {
	var user User
	if err := c.BodyParser(&user); err != nil {
		logger.LogError("invalid user input", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	user.CreatedAt = NowUTC()
	user.UpdatedAt = user.CreatedAt
	created, err := h.Store.CreateUser(c.Context(), user)
	if err != nil {
		logger.LogError("failed to create user", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create user"})
	}
	return c.Status(http.StatusCreated).JSON(created)
}

func (h *Handler) UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	user.ID = id
	user.UpdatedAt = NowUTC()
	updated, err := h.Store.UpdateUser(c.Context(), user)
	if err != nil {
		logger.LogError("failed to update user", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update user"})
	}
	return c.JSON(updated)
}

func (h *Handler) DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	if err := h.Store.DeleteUser(c.Context(), id); err != nil {
		logger.LogError("failed to delete user", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete user"})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *Handler) GetUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	user, err := h.Store.GetUser(c.Context(), id)
	if err != nil {
		logger.LogError("failed to get user", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(user)
}

func (h *Handler) GetUserByEmail(c *fiber.Ctx) error {
	email := c.Query("email")
	if email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing email"})
	}
	user, err := h.Store.GetUserByEmail(c.Context(), email)
	if err != nil {
		logger.LogError("failed to get user by email", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(user)
}

func (h *Handler) ListUsers(c *fiber.Ctx) error {
	status := c.Query("status")
	page := parseIntDefault(c.Query("page"), 1)
	pageSize := parseIntDefault(c.Query("page_size"), 50)
	users, err := h.Store.ListUsers(c.Context(), status, page, pageSize)
	if err != nil {
		logger.LogError("failed to list users", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list users"})
	}
	return c.JSON(users)
}

// --- UserProfile Handlers ---
func (h *Handler) CreateProfile(c *fiber.Ctx) error {
	var profile UserProfile
	if err := c.BodyParser(&profile); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	profile.CreatedAt = NowUTC()
	profile.UpdatedAt = profile.CreatedAt
	created, err := h.Store.CreateProfile(c.Context(), profile)
	if err != nil {
		logger.LogError("failed to create profile", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create profile"})
	}
	return c.Status(http.StatusCreated).JSON(created)
}

func (h *Handler) UpdateProfile(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	var profile UserProfile
	if err := c.BodyParser(&profile); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	profile.UserID = userID
	profile.UpdatedAt = NowUTC()
	updated, err := h.Store.UpdateProfile(c.Context(), profile)
	if err != nil {
		logger.LogError("failed to update profile", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update profile"})
	}
	return c.JSON(updated)
}

func (h *Handler) GetProfile(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	profile, err := h.Store.GetProfile(c.Context(), userID)
	if err != nil {
		logger.LogError("failed to get profile", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "profile not found"})
	}
	return c.JSON(profile)
}

// --- UserSettings Handlers ---
func (h *Handler) GetSettings(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	settings, err := h.Store.GetSettings(c.Context(), userID)
	if err != nil {
		logger.LogError("failed to get settings", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "settings not found"})
	}
	return c.JSON(settings)
}

func (h *Handler) UpdateSettings(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	var req struct {
		Settings string `json:"settings"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.Store.UpdateSettings(c.Context(), userID, req.Settings); err != nil {
		logger.LogError("failed to update settings", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update settings"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// --- UserSession Handlers ---
func (h *Handler) CreateSession(c *fiber.Ctx) error {
	var session UserSession
	if err := c.BodyParser(&session); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	session.CreatedAt = NowUTC()
	created, err := h.Store.CreateSession(c.Context(), session)
	if err != nil {
		logger.LogError("failed to create session", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create session"})
	}
	return c.Status(http.StatusCreated).JSON(created)
}

func (h *Handler) DeleteSession(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing session id"})
	}
	if err := h.Store.DeleteSession(c.Context(), id); err != nil {
		logger.LogError("failed to delete session", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete session"})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *Handler) GetSession(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing session id"})
	}
	session, err := h.Store.GetSession(c.Context(), id)
	if err != nil {
		logger.LogError("failed to get session", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}
	return c.JSON(session)
}

func (h *Handler) ListSessions(c *fiber.Ctx) error {
	userID := c.Query("user_id")
	if userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	page := parseIntDefault(c.Query("page"), 1)
	pageSize := parseIntDefault(c.Query("page_size"), 50)
	sessions, err := h.Store.ListSessions(c.Context(), userID, page, pageSize)
	if err != nil {
		logger.LogError("failed to list sessions", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list sessions"})
	}
	return c.JSON(sessions)
}

// --- UserAuditLog Handlers ---
func (h *Handler) CreateAuditLog(c *fiber.Ctx) error {
	var log UserAuditLog
	if err := c.BodyParser(&log); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	log.CreatedAt = NowUTC()
	created, err := h.Store.CreateAuditLog(c.Context(), log)
	if err != nil {
		logger.LogError("failed to create audit log", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create audit log"})
	}
	return c.Status(http.StatusCreated).JSON(created)
}

func (h *Handler) ListAuditLogs(c *fiber.Ctx) error {
	userID := c.Query("user_id")
	actorID := c.Query("actor_id")
	action := c.Query("action")
	page := parseIntDefault(c.Query("page"), 1)
	pageSize := parseIntDefault(c.Query("page_size"), 50)
	logs, err := h.Store.ListAuditLogs(c.Context(), userID, actorID, action, page, pageSize)
	if err != nil {
		logger.LogError("failed to list audit logs", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list audit logs"})
	}
	return c.JSON(logs)
}

// --- Helpers ---
func parseIntDefault(val string, def int) int {
	if val == "" {
		return def
	}
	var i int
	_, err := fmt.Sscanf(val, "%d", &i)
	if err != nil || i < 1 {
		return def
	}
	return i
}

func NowUTC() (t time.Time) {
	return time.Now().UTC()
}
