package user

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"image/png"
	"net/mail"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"

	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/idencode"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

// UserHandler handles user-related endpoints
// Modular, SaaS-grade, handler-based routing
// All endpoints must be production-ready and secure

// Helper to compute audit log hash
func computeAuditLogHash(id, actorID, action, targetID string, timestamp time.Time, details string) string {
	data := id + actorID + action + targetID + timestamp.UTC().Format(time.RFC3339Nano) + details
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func NewHandler(store UserStore, secrets secrets.SecretsManager, jwtSecretName string, emailSender EmailSender, billingRepo repository.BillingRepository) *UserHandler {
	return &UserHandler{store: store, secrets: secrets, jwtSecretName: jwtSecretName, emailSender: emailSender, billingRepo: billingRepo}
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
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid request body"
		hash := computeAuditLogHash(id, actorID, "system_event", "", timestamp, details)
		if err := h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "system_event",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		}); err != nil {
			// log or handle error
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	ctx := context.Background()
	var u *User
	var err error
	if creds.Username == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	if strings.Contains(creds.Username, "@") {
		u, err = h.getUserByEmail(ctx, creds.Username)
		if err != nil {
			u, err = h.store.GetByUsername(ctx, creds.Username)
		}
	} else {
		u, err = h.store.GetByUsername(ctx, creds.Username)
		if err != nil {
			u, err = h.getUserByEmail(ctx, creds.Username)
		}
	}
	if err != nil || u == nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found or invalid credentials"
		hash := computeAuditLogHash(id, actorID, "system_event", "", timestamp, details)
		if err := h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "system_event",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		}); err != nil {
			// log or handle error
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	ok, err := VerifyPassword(creds.Password, u.PasswordHash)
	if err != nil || !ok {
		id := GenerateUUID()
		actorID := u.ID
		timestamp := time.Now().UTC()
		details := "invalid password"
		hash := computeAuditLogHash(id, actorID, "login_failed", actorID, timestamp, details)
		if err := h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "login_failed",
			TargetID:  actorID,
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		}); err != nil {
			// log or handle error
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	jwtSecret, err := h.secrets.GetSecret(context.Background(), h.jwtSecretName)
	if err != nil || jwtSecret == "" {
		id := GenerateUUID()
		actorID := u.ID
		timestamp := time.Now().UTC()
		details := "server misconfiguration"
		hash := computeAuditLogHash(id, actorID, "system_event", actorID, timestamp, details)
		if err := h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "system_event",
			TargetID:  actorID,
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		}); err != nil {
			// log or handle error
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server misconfiguration"})
	}
	claims := jwt.MapClaims{
		"sub":        u.Username,
		"exp":        time.Now().Add(24 * time.Hour).Unix(),
		"tenant_id":  u.TenantID,
		"roles":      u.Roles,
		"attributes": u.Attributes,
		"type":       "user",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to sign token"})
	}
	// Device/session tracking
	deviceStore, ok := h.store.(UserDeviceStore)
	if ok {
		userAgent := c.Get("User-Agent")
		ip := c.IP()
		devices, _ := deviceStore.ListDevicesByUserID(ctx, u.ID)
		isNew := true
		for _, d := range devices {
			if d.UserAgent == userAgent && d.IP == ip && !d.Revoked {
				isNew = false
				break
			}
		}
		if isNew {
			dev := &UserDevice{
				DeviceID:       GenerateUUID(),
				UserID:         u.ID,
				RefreshTokenID: "", // set after refresh token is created
				UserAgent:      userAgent,
				IP:             ip,
				CreatedAt:      time.Now().UTC(),
				LastSeen:       time.Now().UTC(),
				Revoked:        false,
				Name:           userAgent,
			}
			_ = deviceStore.CreateDevice(ctx, dev)
			_ = h.emailSender.SendDeviceLoginNotification(u.Email, dev.Name, dev.IP, dev.UserAgent)
		}
	}
	id := GenerateUUID()
	actorID := u.ID
	timestamp := time.Now().UTC()
	details := "login successful"
	hash := computeAuditLogHash(id, actorID, "login_success", actorID, timestamp, details)
	if err := h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "login_success",
		TargetID:  actorID,
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	}); err != nil {
		// log or handle error
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"token": tokenString, "type": "user"})
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

func generateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *UserHandler) Logout(c *fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")
	if refreshToken != "" {
		h.store.RevokeRefreshToken(c.Context(), refreshToken)
	}
	c.ClearCookie("refresh_token")
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *UserHandler) Refresh(c *fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing refresh token"})
	}
	t, err := h.store.GetRefreshToken(c.Context(), refreshToken)
	if err != nil || t.Revoked || t.ExpiresAt.Before(time.Now()) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired refresh token"})
	}
	user, err := h.store.GetByID(c.Context(), t.UserID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}
	jwtSecret, err := h.secrets.GetSecret(c.Context(), h.jwtSecretName)
	if err != nil || jwtSecret == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server misconfiguration"})
	}
	claims := jwt.MapClaims{
		"sub":        user.Username,
		"exp":        time.Now().Add(24 * time.Hour).Unix(),
		"tenant_id":  user.TenantID,
		"roles":      user.Roles,
		"attributes": user.Attributes,
		"type":       "user",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to sign token"})
	}
	// Rotate refresh token
	newRefresh, err := generateSecureToken(32)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate refresh token"})
	}
	h.store.RevokeRefreshToken(c.Context(), refreshToken)
	rtok := &RefreshToken{
		TokenID:   GenerateUUID(),
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Token:     newRefresh,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now().UTC(),
		Revoked:   false,
	}
	h.store.CreateRefreshToken(c.Context(), rtok)
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    newRefresh,
		Path:     "/",
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Strict",
		Expires:  rtok.ExpiresAt,
	})
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"token": tokenString, "type": "user"})
}

// getUserByEmail is a real DB lookup via UserStore
func (h *UserHandler) getUserByEmail(ctx context.Context, email string) (*User, error) {
	return h.store.GetByEmail(ctx, email)
}

// sendResetEmail and sendVerificationEmail call the real email provider
func (h *UserHandler) sendResetEmail(email, token string) error {
	return h.emailSender.SendResetEmail(email, token)
}

func (h *UserHandler) sendVerificationEmail(email, token string) error {
	return h.emailSender.SendVerificationEmail(email, token)
}

func (h *UserHandler) ForgotPassword(c *fiber.Ctx) error {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&req); err != nil || req.Email == "" {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid email"
		hash := computeAuditLogHash(id, actorID, "forgot_password_failed", "", timestamp, details)
		if err := h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "forgot_password_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		}); err != nil {
			// log or handle error
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email"})
	}
	if _, err := mail.ParseAddress(req.Email); err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid email format"
		hash := computeAuditLogHash(id, actorID, "forgot_password_failed", "", timestamp, details)
		if err := h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "forgot_password_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		}); err != nil {
			// log or handle error
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email format"})
	}
	ctx := c.Context()
	user, err := h.store.GetByUsername(ctx, req.Email)
	if err != nil {
		user, err = h.getUserByEmail(ctx, req.Email)
		if err != nil {
			id := GenerateUUID()
			actorID := "system"
			timestamp := time.Now().UTC()
			details := "user not found"
			hash := computeAuditLogHash(id, actorID, "forgot_password_failed", "", timestamp, details)
			if err := h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
				ID:        id,
				ActorID:   actorID,
				Action:    "forgot_password_failed",
				TargetID:  "",
				Timestamp: timestamp,
				Details:   details,
				Hash:      hash,
			}); err != nil {
				// log or handle error
			}
			return c.SendStatus(fiber.StatusNoContent)
		}
	}
	token, err := generateSecureToken(32)
	if err != nil {
		id := GenerateUUID()
		actorID := user.ID
		timestamp := time.Now().UTC()
		details := "failed to generate token"
		hash := computeAuditLogHash(id, actorID, "forgot_password_failed", actorID, timestamp, details)
		if err := h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "forgot_password_failed",
			TargetID:  actorID,
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		}); err != nil {
			// log or handle error
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
	reset := &PasswordResetToken{
		Token:     token,
		UserID:    user.ID,
		TenantID:  user.TenantID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
		CreatedAt: time.Now().UTC(),
	}
	h.store.CreatePasswordResetToken(ctx, reset)
	h.sendResetEmail(user.Email, token)
	id := GenerateUUID()
	actorID := user.ID
	timestamp := time.Now().UTC()
	details := "password reset requested"
	hash := computeAuditLogHash(id, actorID, "forgot_password_requested", actorID, timestamp, details)
	if err := h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "forgot_password_requested",
		TargetID:  actorID,
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	}); err != nil {
		// log or handle error
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *UserHandler) ResetPassword(c *fiber.Ctx) error {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil || req.Token == "" || req.Password == "" {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid request"
		hash := computeAuditLogHash(id, actorID, "reset_password_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "reset_password_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	tok, err := h.store.GetPasswordResetToken(c.Context(), req.Token)
	if err != nil || tok.Used || tok.ExpiresAt.Before(time.Now()) {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid or expired token"
		hash := computeAuditLogHash(id, actorID, "reset_password_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "reset_password_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid or expired token"})
	}
	user, err := h.store.GetByID(c.Context(), tok.UserID)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "reset_password_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "reset_password_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user not found"})
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "failed to hash password"
		hash := computeAuditLogHash(id, actorID, "reset_password_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "reset_password_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to hash password"})
	}
	user.PasswordHash = hash
	h.store.Update(c.Context(), user)
	h.store.MarkPasswordResetTokenUsed(c.Context(), req.Token)
	id := GenerateUUID()
	actorID := "system"
	timestamp := time.Now().UTC()
	details := "password reset successful"
	hash = computeAuditLogHash(id, actorID, "reset_password_success", "", timestamp, details)
	h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "reset_password_success",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *UserHandler) VerifyEmail(c *fiber.Ctx) error {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&req); err != nil || req.Token == "" {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid token"
		hash := computeAuditLogHash(id, actorID, "verify_email_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "verify_email_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid token"})
	}
	tok, err := h.store.GetEmailVerificationToken(c.Context(), req.Token)
	if err != nil || tok.Used || tok.ExpiresAt.Before(time.Now()) {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid or expired token"
		hash := computeAuditLogHash(id, actorID, "verify_email_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "verify_email_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid or expired token"})
	}
	user, err := h.store.GetByID(c.Context(), tok.UserID)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "verify_email_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "verify_email_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user not found"})
	}
	user.Attributes["email_verified"] = "true"
	h.store.Update(c.Context(), user)
	h.store.MarkEmailVerificationTokenUsed(c.Context(), req.Token)
	id := GenerateUUID()
	actorID := "system"
	timestamp := time.Now().UTC()
	details := "email verified"
	hash := computeAuditLogHash(id, actorID, "verify_email_success", "", timestamp, details)
	h.billingRepo.CreateAuditLog(c.Context(), &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "verify_email_success",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *UserHandler) ResendVerification(c *fiber.Ctx) error {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&req); err != nil || req.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email"})
	}
	if _, err := mail.ParseAddress(req.Email); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email format"})
	}
	ctx := c.Context()
	user, err := h.store.GetByUsername(ctx, req.Email)
	if err != nil {
		// Try by email if username lookup fails
		user, err = h.getUserByEmail(ctx, req.Email)
		if err != nil {
			return c.SendStatus(fiber.StatusNoContent)
		}
	}
	token, err := generateSecureToken(32)
	if err != nil {
		return c.SendStatus(fiber.StatusNoContent)
	}
	verif := &EmailVerificationToken{
		Token:     token,
		UserID:    user.ID,
		TenantID:  user.TenantID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
		CreatedAt: time.Now().UTC(),
	}
	h.store.CreateEmailVerificationToken(ctx, verif)
	h.sendVerificationEmail(user.Email, token)
	return c.SendStatus(fiber.StatusNoContent)
}

// MFA endpoints for SaaS TOTP (Google Authenticator-style)
func (h *UserHandler) EnrollMFA(c *fiber.Ctx) error {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok || claims["sub"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	username := claims["sub"].(string)
	ctx := c.Context()
	u, err := h.store.GetByUsername(ctx, username)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "mfa_enroll_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_enroll_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}
	if u.IsMFAEnabled() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "MFA already enabled"})
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(GenerateUUID()))
	issuer := "Subinc"
	otpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: u.Email,
		Secret:      []byte(secret),
	})
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "failed to generate TOTP secret"
		hash := computeAuditLogHash(id, actorID, "mfa_enroll_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_enroll_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate TOTP secret"})
	}
	qr, err := otpKey.Image(200, 200)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "failed to generate QR code"
		hash := computeAuditLogHash(id, actorID, "mfa_enroll_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_enroll_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate QR code"})
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, qr); err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "failed to encode QR code"
		hash := computeAuditLogHash(id, actorID, "mfa_enroll_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_enroll_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to encode QR code"})
	}
	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	id := GenerateUUID()
	actorID := "system"
	timestamp := time.Now().UTC()
	details := "MFA enrollment initiated"
	hash := computeAuditLogHash(id, actorID, "mfa_enroll_initiated", "", timestamp, details)
	h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "mfa_enroll_initiated",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.Status(200).JSON(fiber.Map{
		"secret":         secret,
		"otpauth_url":    otpKey.URL(),
		"qr_code_base64": qrBase64,
	})
}

func (h *UserHandler) EnableMFA(c *fiber.Ctx) error {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok || claims["sub"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	username := claims["sub"].(string)
	ctx := c.Context()
	u, err := h.store.GetByUsername(ctx, username)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "mfa_enable_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_enable_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}
	if u.IsMFAEnabled() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "MFA already enabled"})
	}
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Secret == "" || req.Code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	valid := totp.Validate(req.Code, req.Secret)
	if !valid {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "invalid TOTP code"
		hash := computeAuditLogHash(id, actorID, "mfa_enable_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_enable_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid TOTP code"})
	}
	u.SetMFASecret(req.Secret)
	codes := make([]string, 10)
	for i := range codes {
		code, _ := generateSecureToken(8)
		codes[i] = code
	}
	u.SetBackupCodes(codes)
	if err := h.store.Update(ctx, u); err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "failed to persist MFA state"
		hash := computeAuditLogHash(id, actorID, "mfa_enable_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_enable_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to enable MFA"})
	}
	id := GenerateUUID()
	actorID := "system"
	timestamp := time.Now().UTC()
	details := "MFA enabled"
	hash := computeAuditLogHash(id, actorID, "mfa_enabled", "", timestamp, details)
	h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "mfa_enabled",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.Status(200).JSON(fiber.Map{"mfa_enabled": true, "backup_codes": codes})
}

func (h *UserHandler) DisableMFA(c *fiber.Ctx) error {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok || claims["sub"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	username := claims["sub"].(string)
	ctx := c.Context()
	u, err := h.store.GetByUsername(ctx, username)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "mfa_disable_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_disable_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}
	if !u.IsMFAEnabled() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	u.DisableMFA()
	if err := h.store.Update(ctx, u); err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "failed to persist MFA disable"
		hash := computeAuditLogHash(id, actorID, "mfa_disable_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_disable_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to disable MFA"})
	}
	id := GenerateUUID()
	actorID := "system"
	timestamp := time.Now().UTC()
	details := "MFA disabled"
	hash := computeAuditLogHash(id, actorID, "mfa_disabled", "", timestamp, details)
	h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "mfa_disabled",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.Status(200).JSON(fiber.Map{"mfa_enabled": false})
}

func (h *UserHandler) RegenerateBackupCodes(c *fiber.Ctx) error {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok || claims["sub"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	username := claims["sub"].(string)
	ctx := c.Context()
	u, err := h.store.GetByUsername(ctx, username)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "backup_codes_regenerate_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "backup_codes_regenerate_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}
	if !u.IsMFAEnabled() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	codes := make([]string, 10)
	for i := range codes {
		code, _ := generateSecureToken(8)
		codes[i] = code
	}
	u.SetBackupCodes(codes)
	if err := h.store.Update(ctx, u); err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "failed to persist backup codes"
		hash := computeAuditLogHash(id, actorID, "backup_codes_regenerate_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "backup_codes_regenerate_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to regenerate backup codes"})
	}
	id := GenerateUUID()
	actorID := u.ID
	timestamp := time.Now().UTC()
	details := "backup codes regenerated"
	hash := computeAuditLogHash(id, actorID, "backup_codes_regenerated", "", timestamp, details)
	h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "backup_codes_regenerated",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.Status(200).JSON(fiber.Map{"backup_codes": codes})
}

func (h *UserHandler) VerifyMFA(c *fiber.Ctx) error {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok || claims["sub"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	username := claims["sub"].(string)
	ctx := c.Context()
	u, err := h.store.GetByUsername(ctx, username)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "mfa_verify_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_verify_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}
	if !u.IsMFAEnabled() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	valid := false
	if totp.Validate(req.Code, u.MFASecret) {
		valid = true
	} else if u.UseBackupCode(req.Code) {
		valid = true
		h.store.Update(ctx, u) // persist backup code usage
	}
	id := GenerateUUID()
	actorID := u.ID
	timestamp := time.Now().UTC()
	if !valid {
		details := "invalid MFA code"
		hash := computeAuditLogHash(id, actorID, "mfa_verify_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "mfa_verify_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid MFA code"})
	}
	details := "MFA verified"
	hash := computeAuditLogHash(id, actorID, "mfa_verified", "", timestamp, details)
	h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "mfa_verified",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.Status(200).JSON(fiber.Map{"mfa_verified": true})
}

func (h *UserHandler) ListBackupCodes(c *fiber.Ctx) error {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok || claims["sub"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	username := claims["sub"].(string)
	ctx := c.Context()
	u, err := h.store.GetByUsername(ctx, username)
	if err != nil {
		id := GenerateUUID()
		actorID := "system"
		timestamp := time.Now().UTC()
		details := "user not found"
		hash := computeAuditLogHash(id, actorID, "backup_codes_list_failed", "", timestamp, details)
		h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
			ID:        id,
			ActorID:   actorID,
			Action:    "backup_codes_list_failed",
			TargetID:  "",
			Timestamp: timestamp,
			Details:   details,
			Hash:      hash,
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}
	if !u.IsMFAEnabled() {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	id := GenerateUUID()
	actorID := u.ID
	timestamp := time.Now().UTC()
	details := "backup codes listed"
	hash := computeAuditLogHash(id, actorID, "backup_codes_listed", "", timestamp, details)
	h.billingRepo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        id,
		ActorID:   actorID,
		Action:    "backup_codes_listed",
		TargetID:  "",
		Timestamp: timestamp,
		Details:   details,
		Hash:      hash,
	})
	return c.Status(200).JSON(fiber.Map{"backup_codes": u.BackupCodes})
}

func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
	user, ok := c.Locals("user").(*User)
	if !ok || user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"id":             user.ID,
		"username":       user.Username,
		"email":          user.Email,
		"roles":          user.Roles,
		"attributes":     user.Attributes,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
		"email_verified": user.EmailVerified,
		"mfa_enabled":    user.MFAEnabled,
		"type":           "user",
	})
}
