package user

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/subinc/subinc-backend/internal/cost/middleware"
	"github.com/subinc/subinc-backend/internal/pkg/idencode"
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
	// RBAC/ABAC endpoints
	users.Post(":id/roles", middleware.RBACMiddleware("admin", "owner"), h.AssignRole)
	users.Delete(":id/roles/:role", middleware.RBACMiddleware("admin", "owner"), h.RemoveRole)
	users.Post(":id/attributes", middleware.RBACMiddleware("admin", "owner"), h.SetAttribute)
	users.Delete(":id/attributes/:key", middleware.RBACMiddleware("admin", "owner"), h.RemoveAttribute)
}

func decodeIDParam(c *fiber.Ctx) (string, error) {
	return idencode.Decode(c.Params("id"))
}

func (h *UserHandler) ListUsers(c *fiber.Ctx) error {
	ctx := c.Context()
	// Extract tenant ID from context (assume middleware sets it)
	tenantID, ok := c.Locals("tenant_id").(string)
	if !ok || tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing tenant id in context"})
	}
	users, err := h.store.ListByTenantID(ctx, tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch users"})
	}
	resp := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		idHash, _ := idencode.Encode(u.ID)
		resp = append(resp, map[string]interface{}{
			"id":         idHash,
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
	id, err := decodeIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user id"})
	}
	ctx := c.Context()
	u, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}
	idHash, _ := idencode.Encode(u.ID)
	resp := struct {
		ID        string `json:"id"`
		TenantID  string `json:"tenant_id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}{
		ID:        idHash,
		TenantID:  u.TenantID,
		Username:  u.Username,
		Email:     u.Email,
		CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (h *UserHandler) DeleteUser(c *fiber.Ctx) error {
	id, err := decodeIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user id"})
	}
	ctx := c.Context()
	err = h.store.Delete(ctx, id)
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
	id, err := decodeIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user id"})
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

func (h *UserHandler) AssignRole(c *fiber.Ctx) error {
	id, err := decodeIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user id"})
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil || req.Role == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid role"})
	}
	ctx := context.Background()
	u, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	// Enforce tenant isolation
	claims, _ := c.Locals("claims").(map[string]interface{})
	if claims["tenant_id"] != u.TenantID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	u.AddRole(req.Role)
	if err := h.store.Update(ctx, u); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to update user roles"})
	}
	return c.JSON(fiber.Map{"roles": u.Roles})
}

func (h *UserHandler) RemoveRole(c *fiber.Ctx) error {
	id, err := decodeIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user id"})
	}
	role := c.Params("role")
	if role == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid role"})
	}
	ctx := context.Background()
	u, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	claims, _ := c.Locals("claims").(map[string]interface{})
	if claims["tenant_id"] != u.TenantID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	u.RemoveRole(role)
	if err := h.store.Update(ctx, u); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to update user roles"})
	}
	return c.JSON(fiber.Map{"roles": u.Roles})
}

func (h *UserHandler) SetAttribute(c *fiber.Ctx) error {
	id, err := decodeIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user id"})
	}
	var req struct{ Key, Value string }
	if err := c.BodyParser(&req); err != nil || req.Key == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid attribute"})
	}
	ctx := context.Background()
	u, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	claims, _ := c.Locals("claims").(map[string]interface{})
	if claims["tenant_id"] != u.TenantID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	u.SetAttribute(req.Key, req.Value)
	if err := h.store.Update(ctx, u); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to update user attributes"})
	}
	return c.JSON(fiber.Map{"attributes": u.Attributes})
}

func (h *UserHandler) RemoveAttribute(c *fiber.Ctx) error {
	id, err := decodeIDParam(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user id"})
	}
	key := c.Params("key")
	if key == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid attribute key"})
	}
	ctx := context.Background()
	u, err := h.store.GetByID(ctx, id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	claims, _ := c.Locals("claims").(map[string]interface{})
	if claims["tenant_id"] != u.TenantID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	u.RemoveAttribute(key)
	if err := h.store.Update(ctx, u); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to update user attributes"})
	}
	return c.JSON(fiber.Map{"attributes": u.Attributes})
}
