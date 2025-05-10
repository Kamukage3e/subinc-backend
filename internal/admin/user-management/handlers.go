package user_management

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type UserHandler struct {
	Store *PostgresStore
}

func NewUserHandler(store *PostgresStore) *UserHandler {
	return &UserHandler{Store: store}
}

// --- User Handlers ---
func (h *UserHandler) CreateUser(c *fiber.Ctx) error {
	var user User
	if err := c.BodyParser(&user); err != nil {
		logger.LogError("invalid user input", logger.ErrorField(err))
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := user.Validate(); err != nil {
		logger.LogError("CreateUser: validation failed", logger.ErrorField(err))
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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

func (h *UserHandler) UpdateUser(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
		User
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	if err := input.User.Validate(); err != nil {
		logger.LogError("UpdateUser: validation failed", logger.ErrorField(err))
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	input.User.ID = input.ID
	input.User.UpdatedAt = NowUTC()
	updated, err := h.Store.UpdateUser(c.Context(), input.User)
	if err != nil {
		logger.LogError("failed to update user", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update user"})
	}
	return c.JSON(updated)
}

func (h *UserHandler) DeleteUser(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	if err := h.Store.DeleteUser(c.Context(), input.ID); err != nil {
		logger.LogError("failed to delete user", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete user"})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *UserHandler) GetUser(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	user, err := h.Store.GetUser(c.Context(), input.ID)
	if err != nil {
		logger.LogError("failed to get user", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(user)
}

func (h *UserHandler) GetUserByEmail(c *fiber.Ctx) error {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing email"})
	}
	user, err := h.Store.GetUserByEmail(c.Context(), input.Email)
	if err != nil {
		logger.LogError("failed to get user by email", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(user)
}

func (h *UserHandler) ListUsers(c *fiber.Ctx) error {
	var input struct {
		Status   string `json:"status"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 50
	}
	users, err := h.Store.ListUsers(c.Context(), input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("failed to list users", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list users"})
	}
	return c.JSON(users)
}

// --- UserProfile Handlers ---
func (h *UserHandler) CreateProfile(c *fiber.Ctx) error {
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

func (h *UserHandler) UpdateProfile(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
		UserProfile
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	input.UserProfile.UserID = input.UserID
	input.UserProfile.UpdatedAt = NowUTC()
	updated, err := h.Store.UpdateProfile(c.Context(), input.UserProfile)
	if err != nil {
		logger.LogError("failed to update profile", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update profile"})
	}
	return c.JSON(updated)
}

func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	profile, err := h.Store.GetProfile(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("failed to get profile", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "profile not found"})
	}
	return c.JSON(profile)
}

// --- UserSettings Handlers ---
func (h *UserHandler) GetSettings(c *fiber.Ctx) error {
	var input struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	settings, err := h.Store.GetSettings(c.Context(), input.UserID)
	if err != nil {
		logger.LogError("failed to get settings", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "settings not found"})
	}
	return c.JSON(settings)
}

func (h *UserHandler) UpdateSettings(c *fiber.Ctx) error {
	var input struct {
		UserID   string `json:"user_id"`
		Settings string `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	if err := h.Store.UpdateSettings(c.Context(), input.UserID, input.Settings); err != nil {
		logger.LogError("failed to update settings", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update settings"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// --- UserSession Handlers ---
func (h *UserHandler) CreateSession(c *fiber.Ctx) error {
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

func (h *UserHandler) DeleteSession(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing session id"})
	}
	if err := h.Store.DeleteSession(c.Context(), input.ID); err != nil {
		logger.LogError("failed to delete session", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete session"})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *UserHandler) GetSession(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing session id"})
	}
	session, err := h.Store.GetSession(c.Context(), input.ID)
	if err != nil {
		logger.LogError("failed to get session", logger.ErrorField(err))
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "session not found"})
	}
	return c.JSON(session)
}

func (h *UserHandler) ListSessions(c *fiber.Ctx) error {
	var input struct {
		UserID   string `json:"user_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 50
	}
	sessions, err := h.Store.ListSessions(c.Context(), input.UserID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("failed to list sessions", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list sessions"})
	}
	return c.JSON(sessions)
}

func NowUTC() (t time.Time) {
	return time.Now().UTC()
}

func (u *User) Validate() error {
	if u.Email == "" {
		return fiber.NewError(http.StatusUnprocessableEntity, "email must not be empty")
	}
	if len(u.Email) > 256 {
		return fiber.NewError(http.StatusUnprocessableEntity, "email too long")
	}
	if u.Password == "" {
		return fiber.NewError(http.StatusUnprocessableEntity, "password must not be empty")
	}
	if len(u.Password) < 8 {
		return fiber.NewError(http.StatusUnprocessableEntity, "password too short")
	}
	return nil
}
