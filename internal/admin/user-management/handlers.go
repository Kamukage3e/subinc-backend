package user_management

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewUserHandler(store *PostgresStore) *UserHandler {
	return &UserHandler{Store: store}
}

// getActorID extracts the user_id from fiber context or returns "system" if not present
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

// swagger:route POST /users user createUser
// summary: Create a user
// description: Creates a new user.
// tags:
//   - user
//
// responses:
//
//	201: User
//	400: ErrorResponse
//	422: ErrorResponse
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

// swagger:route PUT /users/:id user updateUser
// summary: Update a user
// description: Updates an existing user.
// tags:
//   - user
//
// responses:
//
//	200: User
//	400: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := user.Validate(); err != nil {
		logger.LogError("UpdateUser: validation failed", logger.ErrorField(err))
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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

// swagger:route DELETE /users/:id user deleteUser
// summary: Delete a user
// description: Deletes a user by ID.
// tags:
//   - user
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) DeleteUser(c *fiber.Ctx) error {
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

// swagger:route GET /users/:id user getUser
// summary: Get a user
// description: Retrieves a user by ID.
// tags:
//   - user
//
// responses:
//
//	200: User
//	400: ErrorResponse
//	404: ErrorResponse
func (h *UserHandler) GetUser(c *fiber.Ctx) error {
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

// swagger:route GET /users/email/:email user getUserByEmail
// summary: Get user by email
// description: Retrieves a user by email address.
// tags:
//   - user
//
// responses:
//
//	200: User
//	400: ErrorResponse
//	404: ErrorResponse
func (h *UserHandler) GetUserByEmail(c *fiber.Ctx) error {
	email := c.Params("email")
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

// swagger:route GET /users user listUsers
// summary: List users
// description: Lists users with optional filters.
// tags:
//   - user
//
// responses:
//
//	200: UserListResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) ListUsers(c *fiber.Ctx) error {
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 50)
	users, err := h.Store.ListUsers(c.Context(), status, page, pageSize)
	if err != nil {
		logger.LogError("failed to list users", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list users"})
	}
	return c.JSON(users)
}

// swagger:route POST /profiles user createProfile
// summary: Create a user profile
// description: Creates a new user profile.
// tags:
//   - user
//   - profile
//
// responses:
//
//	201: UserProfile
//	400: ErrorResponse
//	422: ErrorResponse
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

// swagger:route PUT /profiles/:user_id user updateProfile
// summary: Update a user profile
// description: Updates an existing user profile.
// tags:
//   - user
//   - profile
//
// responses:
//
//	200: UserProfile
//	400: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) UpdateProfile(c *fiber.Ctx) error {
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

// swagger:route GET /profiles/:user_id user getProfile
// summary: Get a user profile
// description: Retrieves a user profile by user ID.
// tags:
//   - user
//   - profile
//
// responses:
//
//	200: UserProfile
//	400: ErrorResponse
//	404: ErrorResponse
func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
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

// swagger:route GET /settings/:user_id user getSettings
// summary: Get user settings
// description: Retrieves user settings by user ID.
// tags:
//   - user
//   - settings
//
// responses:
//
//	200: UserSettings
//	400: ErrorResponse
//	404: ErrorResponse
func (h *UserHandler) GetSettings(c *fiber.Ctx) error {
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

// swagger:route PUT /settings/:user_id user updateSettings
// summary: Update user settings
// description: Updates user settings by user ID.
// tags:
//   - user
//   - settings
//
// responses:
//
//	200: UpdateSettingsResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) UpdateSettings(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	var input struct {
		Settings map[string]interface{} `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.Store.UpdateSettings(c.Context(), userID, input.Settings); err != nil {
		logger.LogError("failed to update settings", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update settings"})
	}
	return c.JSON(fiber.Map{"ok": true})
}

// swagger:route PUT /orgs/:org_id/users/:user_id user addUserToOrg
// summary: Add user to organization
// description: Adds a user to an organization.
// tags:
//   - user
//   - org
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) AddUserToOrg(c *fiber.Ctx) error {
	orgID := c.Params("org_id")
	userID := c.Params("user_id")
	if orgID == "" || userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id and user_id required"})
	}
	var input struct {
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	err := h.Store.AddUserToOrg(c.Context(), orgID, userID, input.InvitedBy, input.Role)
	if err != nil {
		logger.LogError("AddUserToOrg failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to add user to org"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route DELETE /orgs/:org_id/users/:user_id user removeUserFromOrg
// summary: Remove user from organization
// description: Removes a user from an organization.
// tags:
//   - user
//   - org
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) RemoveUserFromOrg(c *fiber.Ctx) error {
	orgID := c.Params("org_id")
	userID := c.Params("user_id")
	if orgID == "" || userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id and user_id required"})
	}
	err := h.Store.RemoveUserFromOrg(c.Context(), orgID, userID)
	if err != nil {
		logger.LogError("RemoveUserFromOrg failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to remove user from org"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route GET /orgs/:org_id/users user listOrgUsers
// summary: List organization users
// description: Lists users in an organization.
// tags:
//   - user
//   - org
//
// responses:
//
//	200: UserListResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) ListOrgUsers(c *fiber.Ctx) error {
	orgID := c.Params("org_id")
	if orgID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id required"})
	}
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 50)
	users, err := h.Store.ListOrgUsers(c.Context(), orgID, page, pageSize)
	if err != nil {
		logger.LogError("ListOrgUsers failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list org users"})
	}
	return c.JSON(users)
}

// swagger:route POST /orgs/:org_id/invites user inviteUserToOrg
// summary: Invite user to organization
// description: Invites a user to an organization by email.
// tags:
//   - user
//   - org
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) InviteUserToOrg(c *fiber.Ctx) error {
	orgID := c.Params("org_id")
	if orgID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id required"})
	}
	var input struct {
		Email     string `json:"email"`
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "email required"})
	}
	err := h.Store.InviteUserToOrg(c.Context(), orgID, input.Email, input.InvitedBy, input.Role)
	if err != nil {
		logger.LogError("InviteUserToOrg failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to invite user to org"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route PUT /projects/:project_id/users/:user_id user addUserToProject
// summary: Add user to project
// description: Adds a user to a project.
// tags:
//   - user
//   - project
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) AddUserToProject(c *fiber.Ctx) error {
	projectID := c.Params("project_id")
	userID := c.Params("user_id")
	if projectID == "" || userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id and user_id required"})
	}
	var input struct {
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	err := h.Store.AddUserToProject(c.Context(), projectID, userID, input.InvitedBy, input.Role)
	if err != nil {
		logger.LogError("AddUserToProject failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to add user to project"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route DELETE /projects/:project_id/users/:user_id user removeUserFromProject
// summary: Remove user from project
// description: Removes a user from a project.
// tags:
//   - user
//   - project
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) RemoveUserFromProject(c *fiber.Ctx) error {
	projectID := c.Params("project_id")
	userID := c.Params("user_id")
	if projectID == "" || userID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id and user_id required"})
	}
	err := h.Store.RemoveUserFromProject(c.Context(), projectID, userID)
	if err != nil {
		logger.LogError("RemoveUserFromProject failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to remove user from project"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route GET /projects/:project_id/users user listProjectUsers
// summary: List project users
// description: Lists users in a project.
// tags:
//   - user
//   - project
//
// responses:
//
//	200: UserListResponse
//	400: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) ListProjectUsers(c *fiber.Ctx) error {
	projectID := c.Params("project_id")
	if projectID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id required"})
	}
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 50)
	users, err := h.Store.ListProjectUsers(c.Context(), projectID, page, pageSize)
	if err != nil {
		logger.LogError("ListProjectUsers failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list project users"})
	}
	return c.JSON(users)
}

// swagger:route POST /projects/:project_id/invites user inviteUserToProject
// summary: Invite user to project
// description: Invites a user to a project by email.
// tags:
//   - user
//   - project
//
// responses:
//
//	204: EmptyResponse
//	400: ErrorResponse
//	403: ErrorResponse
//	422: ErrorResponse
func (h *UserHandler) InviteUserToProject(c *fiber.Ctx) error {
	projectID := c.Params("project_id")
	if projectID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id required"})
	}
	var input struct {
		Email     string `json:"email"`
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil || input.Email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "email required"})
	}
	err := h.Store.InviteUserToProject(c.Context(), projectID, input.Email, input.InvitedBy, input.Role)
	if err != nil {
		logger.LogError("InviteUserToProject failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to invite user to project"})
	}
	return c.SendStatus(http.StatusNoContent)
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
