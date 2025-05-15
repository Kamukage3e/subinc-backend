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

// swagger:route POST /user-management/users/create user createUser
// ---
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "user", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

// swagger:route PUT /user-management/users/update user updateUser
// ---
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

// swagger:route DELETE /user-management/users/delete user deleteUser
// ---
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

// swagger:route GET /user-management/users/get user getUser
// ---
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

// swagger:route GET /user-management/users/get-by-email user getUserByEmail
// ---
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

// swagger:route GET /user-management/users/list user listUsers
// ---
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
// swagger:route POST /user-management/profiles/create user createProfile
// ---
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

// swagger:route PUT /user-management/profiles/update user updateProfile
// ---
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

// swagger:route GET /user-management/profiles/get user getProfile
// ---
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
// swagger:route GET /user-management/settings/get user getSettings
// ---
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

// swagger:route PUT /user-management/settings/update user updateSettings
// ---
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
	var input struct {
		UserID   string                 `json:"user_id"`
		Settings map[string]interface{} `json:"settings"`
	}
	if err := c.BodyParser(&input); err != nil || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	if err := h.Store.UpdateSettings(c.Context(), input.UserID, input.Settings); err != nil {
		logger.LogError("failed to update settings", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update settings"})
	}
	// Optionally: test connection/feature if settings include credentials, return result
	return c.JSON(fiber.Map{"ok": true})
}

// --- Org/Project Membership/Invite Handlers ---

// swagger:route POST /user-management/orgs/add-user user addUserToOrg
// ---
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "org_member", "add")
		if err != nil || !permitted {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		OrgID     string `json:"org_id"`
		UserID    string `json:"user_id"`
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil || input.OrgID == "" || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id and user_id required"})
	}
	err := h.Store.AddUserToOrg(c.Context(), input.OrgID, input.UserID, input.InvitedBy, input.Role)
	if err != nil {
		logger.LogError("AddUserToOrg failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to add user to org"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route DELETE /user-management/orgs/remove-user user removeUserFromOrg
// ---
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "org_member", "remove")
		if err != nil || !permitted {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		OrgID  string `json:"org_id"`
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.OrgID == "" || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id and user_id required"})
	}
	err := h.Store.RemoveUserFromOrg(c.Context(), input.OrgID, input.UserID)
	if err != nil {
		logger.LogError("RemoveUserFromOrg failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to remove user from org"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route GET /user-management/orgs/list-users user listOrgUsers
// ---
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
	var input struct {
		OrgID    string `json:"org_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil || input.OrgID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id required"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 50
	}
	users, err := h.Store.ListOrgUsers(c.Context(), input.OrgID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListOrgUsers failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list org users"})
	}
	return c.JSON(users)
}

// swagger:route POST /user-management/orgs/invite-user user inviteUserToOrg
// ---
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "org_invite", "invite")
		if err != nil || !permitted {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		OrgID     string `json:"org_id"`
		Email     string `json:"email"`
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil || input.OrgID == "" || input.Email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "org_id and email required"})
	}
	err := h.Store.InviteUserToOrg(c.Context(), input.OrgID, input.Email, input.InvitedBy, input.Role)
	if err != nil {
		logger.LogError("InviteUserToOrg failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to invite user to org"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route POST /user-management/projects/add-user user addUserToProject
// ---
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "project_member", "add")
		if err != nil || !permitted {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ProjectID string `json:"project_id"`
		UserID    string `json:"user_id"`
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil || input.ProjectID == "" || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id and user_id required"})
	}
	err := h.Store.AddUserToProject(c.Context(), input.ProjectID, input.UserID, input.InvitedBy, input.Role)
	if err != nil {
		logger.LogError("AddUserToProject failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to add user to project"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route DELETE /user-management/projects/remove-user user removeUserFromProject
// ---
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "project_member", "remove")
		if err != nil || !permitted {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ProjectID string `json:"project_id"`
		UserID    string `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ProjectID == "" || input.UserID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id and user_id required"})
	}
	err := h.Store.RemoveUserFromProject(c.Context(), input.ProjectID, input.UserID)
	if err != nil {
		logger.LogError("RemoveUserFromProject failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to remove user from project"})
	}
	return c.SendStatus(http.StatusNoContent)
}

// swagger:route GET /user-management/projects/list-users user listProjectUsers
// ---
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
	var input struct {
		ProjectID string `json:"project_id"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil || input.ProjectID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id required"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 50
	}
	users, err := h.Store.ListProjectUsers(c.Context(), input.ProjectID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListProjectUsers failed", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list project users"})
	}
	return c.JSON(users)
}

// swagger:route POST /user-management/projects/invite-user user inviteUserToProject
// ---
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
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "project_invite", "invite")
		if err != nil || !permitted {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ProjectID string `json:"project_id"`
		Email     string `json:"email"`
		InvitedBy string `json:"invited_by"`
		Role      string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil || input.ProjectID == "" || input.Email == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "project_id and email required"})
	}
	err := h.Store.InviteUserToProject(c.Context(), input.ProjectID, input.Email, input.InvitedBy, input.Role)
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
