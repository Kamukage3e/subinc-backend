package user

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

// UserHandler handles user-related endpoints
// Modular, SaaS-grade, handler-based routing
// All endpoints must be production-ready and secure

type UserHandler struct {
	store         UserStore
	secrets       secrets.SecretsManager
	jwtSecretName string
}

func NewHandler(store UserStore, secrets secrets.SecretsManager, jwtSecretName string) *UserHandler {
	return &UserHandler{store: store, secrets: secrets, jwtSecretName: jwtSecretName}
}

func (h *UserHandler) RegisterRoutes(router fiber.Router) {
	users := router.Group("/users")

	users.Get("/", h.ListUsers)
	users.Get(":id", h.GetUserByID)
	users.Put(":id", h.UpdateUser)
	users.Delete(":id", h.DeleteUser)
	users.Post("/login", h.Login)
	users.Post("/register", h.Register)
}

func (h *UserHandler) ListUsers(c *fiber.Ctx) error {
	ctx := c.Context()
	// Extract tenant ID from context (assume middleware sets it)
	tenantID, ok := c.Locals("tenant_id").(string)
	if !ok || tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing tenant id in context"})
	}
	// Implement a real ListUsers method in your UserStore for prod
	users, err := h.store.ListByTenantID(ctx, tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch users"})
	}
	resp := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		resp = append(resp, map[string]interface{}{
			"id":         u.ID,
			"tenant_id":  u.TenantID,
			"username":   u.Username,
			"email":      u.Email,
			"roles":      u.Roles,
			"attributes": u.Attributes,
			"created_at": u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			"updated_at": u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h *UserHandler) GetUserByID(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	ctx := c.Context()
	u, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	resp := struct {
		ID        string `json:"id"`
		TenantID  string `json:"tenant_id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}{
		ID:        u.ID,
		TenantID:  u.TenantID,
		Username:  u.Username,
		Email:     u.Email,
		CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h *UserHandler) DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	ctx := c.Context()
	err := h.store.Delete(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *UserHandler) Login(c *fiber.Ctx) error {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&creds); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	ctx := context.Background()
	u, err := h.store.GetByUsername(ctx, creds.Username)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	ok, err := VerifyPassword(creds.Password, u.PasswordHash)
	if err != nil || !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	jwtSecret, err := h.secrets.GetSecret(context.Background(), h.jwtSecretName)
	if err != nil || jwtSecret == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server misconfiguration"})
	}
	claims := jwt.MapClaims{
		"sub":        u.Username,
		"exp":        time.Now().Add(24 * time.Hour).Unix(),
		"tenant_id":  u.TenantID,
		"roles":      u.Roles,
		"attributes": u.Attributes,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to sign token"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"token": tokenString})
}

func (h *UserHandler) Register(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if req.Username == "" || req.Email == "" || req.Password == "" || req.TenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing required fields"})
	}
	ctx := c.Context()
	_, err := h.store.GetByUsername(ctx, req.Username)
	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "username already exists"})
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password"})
	}
	u := &User{
		ID:           GenerateUUID(),
		TenantID:     req.TenantID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		Roles:        []string{"user"},
		Attributes:   map[string]string{},
	}
	if err := h.store.Create(ctx, u); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create user"})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": u.ID, "username": u.Username, "email": u.Email, "tenant_id": u.TenantID})
}

func (h *UserHandler) UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing user id"})
	}
	var req struct {
		Email      *string            `json:"email"`
		Password   *string            `json:"password"`
		Roles      *[]string          `json:"roles"`
		Attributes *map[string]string `json:"attributes"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	ctx := c.Context()
	u, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	if req.Email != nil && *req.Email != "" {
		u.Email = *req.Email
	}
	if req.Password != nil && *req.Password != "" {
		hash, err := HashPassword(*req.Password)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password"})
		}
		u.PasswordHash = hash
	}
	if req.Roles != nil {
		u.Roles = *req.Roles
	}
	if req.Attributes != nil {
		u.Attributes = *req.Attributes
	}
	u.UpdatedAt = time.Now().UTC()
	if err := h.store.Update(ctx, u); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update user"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"id": u.ID, "username": u.Username, "email": u.Email, "tenant_id": u.TenantID})
}
