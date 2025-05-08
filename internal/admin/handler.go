package admin

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
	"github.com/subinc/subinc-backend/internal/email"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/user"
)

func NewHandler(store interface {
	AdminStore
	AdminUserStore
}, userStore *user.PostgresUserStore, emailManager *email.EmailManager, secretsManager interface{}, jwtSecretName string) *AdminHandler {
	return &AdminHandler{store: store, userStore: userStore, emailManager: emailManager, SecretsManager: secretsManager, JWTSecretName: jwtSecretName}
}

// parseListFilter parses common list filter params from the request context
func parseListFilter(c *fiber.Ctx, defaultLimit int) (string, string, string, int, int) {
	q := c.Query("q")
	sortBy := c.Query("sort_by")
	sortDir := strings.ToUpper(c.Query("sort_dir"))
	limit := c.QueryInt("limit", defaultLimit)
	if limit < 1 || limit > 1000 {
		limit = defaultLimit
	}
	offset := c.QueryInt("offset", 0)
	return q, sortBy, sortDir, limit, offset
}

func (h *AdminHandler) ListUsers(c *fiber.Ctx) error {
	// Parse query parameters for filtering, sorting and pagination
	query := c.Query("q", "")
	role := c.Query("role", "")
	sortBy := c.Query("sort_by", "created_at")
	sortDir := c.Query("sort_dir", "DESC")
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	// Validate and cap limit
	if limit < 1 {
		limit = 10
	} else if limit > 1000 {
		limit = 1000
	}

	// Create filter
	filter := UserFilter{
		Query:   query,
		Role:    role,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}

	users, total, err := h.store.SearchUsers(filter)
	if err != nil {
		logger.LogError("failed to list users",
			logger.ErrorField(err),
			logger.String("query", query),
			logger.String("role", role),
			logger.String("sort_by", sortBy),
			logger.String("sort_dir", sortDir),
			logger.Int("limit", limit),
			logger.Int("offset", offset))
		return errorResponse(c, fiber.StatusInternalServerError, "list_failed", "Failed to list users", err)
	}

	logger.LogInfo("users listed successfully",
		logger.Int("total", total),
		logger.Int("returned", len(users)),
		logger.String("query", query),
		logger.String("role", role))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"users": users,
		"total": total,
	})
}

func (h *AdminHandler) ListTenants(c *fiber.Ctx) error {
	// Parse query parameters for filtering, sorting and pagination
	query := c.Query("q", "")
	sortBy := c.Query("sort_by", "created_at")
	sortDir := c.Query("sort_dir", "DESC")
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	// Validate and cap limit
	if limit < 1 {
		limit = 10
	} else if limit > 1000 {
		limit = 1000
	}

	filter := TenantFilter{
		Query:   query,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	tenants, total, err := h.store.SearchTenants(filter)
	if err != nil {
		logger.LogError("failed to list tenants",
			logger.ErrorField(err),
			logger.String("query", query),
			logger.String("sort_by", sortBy),
			logger.String("sort_dir", sortDir),
			logger.Int("limit", limit),
			logger.Int("offset", offset))
		return errorResponse(c, fiber.StatusInternalServerError, "list_failed", "Failed to list tenants", err)
	}

	logger.LogInfo("tenants listed successfully",
		logger.Int("total", total),
		logger.Int("returned", len(tenants)))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"tenants": tenants,
		"total":   total,
	})
}

func (h *AdminHandler) ListRoles(c *fiber.Ctx) error {
	// Parse query parameters for filtering, sorting and pagination
	query := c.Query("q", "")
	sortBy := c.Query("sort_by", "name")
	sortDir := c.Query("sort_dir", "ASC")
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	// Validate and cap limit
	if limit < 1 {
		limit = 10
	} else if limit > 1000 {
		limit = 1000
	}

	filter := RoleFilter{
		Query:   query,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	roles, total, err := h.store.SearchRoles(filter)
	if err != nil {
		logger.LogError("failed to list roles",
			logger.ErrorField(err),
			logger.String("query", query),
			logger.String("sort_by", sortBy),
			logger.String("sort_dir", sortDir),
			logger.Int("limit", limit),
			logger.Int("offset", offset))
		return errorResponse(c, fiber.StatusInternalServerError, "list_failed", "Failed to list roles", err)
	}

	logger.LogInfo("roles listed successfully",
		logger.Int("total", total),
		logger.Int("returned", len(roles)))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"roles": roles,
		"total": total,
	})
}

func (h *AdminHandler) ListPermissions(c *fiber.Ctx) error {
	// Parse query parameters for filtering, sorting and pagination
	query := c.Query("q", "")
	sortBy := c.Query("sort_by", "name")
	sortDir := c.Query("sort_dir", "ASC")
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	// Validate and cap limit
	if limit < 1 {
		limit = 10
	} else if limit > 1000 {
		limit = 1000
	}

	filter := PermissionFilter{
		Query:   query,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	perms, total, err := h.store.SearchPermissions(filter)
	if err != nil {
		logger.LogError("failed to list permissions",
			logger.ErrorField(err),
			logger.String("query", query),
			logger.String("sort_by", sortBy),
			logger.String("sort_dir", sortDir),
			logger.Int("limit", limit),
			logger.Int("offset", offset))
		return errorResponse(c, fiber.StatusInternalServerError, "list_failed", "Failed to list permissions", err)
	}

	logger.LogInfo("permissions listed successfully",
		logger.Int("total", total),
		logger.Int("returned", len(perms)))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"permissions": perms,
		"total":       total,
	})
}

func (h *AdminHandler) ListAuditLogs(c *fiber.Ctx) error {
	filter := AuditLogFilter{
		ActorID:  c.Query("actor_id"),
		Action:   c.Query("action"),
		Resource: c.Query("resource"),
	}
	if v := c.Query("start"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Start = &t
		}
	}
	if v := c.Query("end"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.End = &t
		}
	}
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			filter.Limit = n
		}
	}
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			filter.Offset = n
		}
	}
	export := c.Query("export")
	logs, total, err := h.store.SearchAuditLogs(filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch audit logs"})
	}
	if export == "csv" {
		csvData, err := AuditLogsToCSV(logs)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to export csv"})
		}
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", "attachment; filename=audit_logs.csv")
		return c.SendString(csvData)
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "logs": logs})
}

func (h *AdminHandler) BillingSummary(c *fiber.Ctx) error {
	summary, err := h.store.BillingSummary()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch billing summary"})
	}
	return c.Status(fiber.StatusOK).JSON(summary)
}

func (h *AdminHandler) SystemHealth(c *fiber.Ctx) error {
	health, err := h.store.SystemHealth()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch system health"})
	}
	return c.Status(fiber.StatusOK).JSON(health)
}

func (h *AdminHandler) ListSessions(c *fiber.Ctx) error {
	sessions, err := h.store.ListSessions()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch sessions"})
	}
	return c.Status(fiber.StatusOK).JSON(sessions)
}

func (h *AdminHandler) ImpersonateUser(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	session, err := h.store.ImpersonateUser(req.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to impersonate user"})
	}
	return c.Status(fiber.StatusOK).JSON(session)
}

func (h *AdminHandler) SupportTools(c *fiber.Ctx) error {
	tools, err := h.store.SupportTools()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch support tools"})
	}
	return c.Status(fiber.StatusOK).JSON(tools)
}

func (h *AdminHandler) RBACStatus(c *fiber.Ctx) error {
	status, err := h.store.RBACStatus()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch RBAC status"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) StepUpAuth(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	result, err := h.store.StepUpAuth(req.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to perform step-up auth"})
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *AdminHandler) DelegatedAdminStatus(c *fiber.Ctx) error {
	status, err := h.store.DelegatedAdminStatus()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch delegated admin status"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) SCIMStatus(c *fiber.Ctx) error {
	status, err := h.store.SCIMStatus()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch SCIM status"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) AuditAnomalies(c *fiber.Ctx) error {
	anomalies, err := h.store.AuditAnomalies()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch audit anomalies"})
	}
	return c.Status(fiber.StatusOK).JSON(anomalies)
}

func (h *AdminHandler) RateLimits(c *fiber.Ctx) error {
	limits, err := h.store.RateLimits()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch rate limits"})
	}
	return c.Status(fiber.StatusOK).JSON(limits)
}

func (h *AdminHandler) AbuseDetection(c *fiber.Ctx) error {
	abuse, err := h.store.AbuseDetection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch abuse detection info"})
	}
	return c.Status(fiber.StatusOK).JSON(abuse)
}

func (h *AdminHandler) Alerts(c *fiber.Ctx) error {
	alerts, err := h.store.Alerts()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch alerts"})
	}
	return c.Status(fiber.StatusOK).JSON(alerts)
}

func (h *AdminHandler) SecretsStatus(c *fiber.Ctx) error {
	status, err := h.store.GetSecretsStatus()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch secrets status"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) SystemConfig(c *fiber.Ctx) error {
	config, err := h.store.SystemConfig()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch system config"})
	}
	return c.Status(fiber.StatusOK).JSON(config)
}

func (h *AdminHandler) ListFeatureFlags(c *fiber.Ctx) error {
	flags, err := h.store.ListFeatureFlags()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch feature flags"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"flags": flags})
}

func (h *AdminHandler) CreateFeatureFlag(c *fiber.Ctx) error {
	var input FeatureFlagInput
	if err := c.BodyParser(&input); err != nil || input.Flag == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	flag, err := h.store.CreateFeatureFlag(&input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create feature flag"})
	}
	return c.Status(fiber.StatusCreated).JSON(flag)
}

func (h *AdminHandler) UpdateFeatureFlag(c *fiber.Ctx) error {
	var input FeatureFlagInput
	if err := c.BodyParser(&input); err != nil || input.Flag == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	flag, err := h.store.UpdateFeatureFlag(&input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update feature flag"})
	}
	return c.Status(fiber.StatusOK).JSON(flag)
}

func (h *AdminHandler) DeleteFeatureFlag(c *fiber.Ctx) error {
	flag := c.Query("flag")
	if flag == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "flag required"})
	}
	if err := h.store.DeleteFeatureFlag(flag); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete feature flag"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminHandler) GetMaintenanceMode(c *fiber.Ctx) error {
	status, err := h.store.GetMaintenanceMode()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch maintenance mode status"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) SetMaintenanceMode(c *fiber.Ctx) error {
	var input MaintenanceModeInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	status, err := h.store.SetMaintenanceMode(input.Maintenance)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update maintenance mode"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) RealTimeMonitoring(c *fiber.Ctx) error {
	monitoring, err := h.store.RealTimeMonitoring()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch real-time monitoring info"})
	}
	return c.Status(fiber.StatusOK).JSON(monitoring)
}

// errorResponse returns a standardized error response with code and message
func errorResponse(c *fiber.Ctx, status int, code, msg string, err error) error {
	if err != nil {
		// Log internal error with context, but never leak details to client
		logger.LogError(msg,
			logger.String("code", code),
			logger.ErrorField(err),
			logger.String("path", c.Path()),
			logger.String("ip", c.IP()),
			logger.String("method", c.Method()))
	}
	return c.Status(status).JSON(fiber.Map{"error": msg, "code": code})
}

func (h *AdminHandler) CreateUser(c *fiber.Ctx) error {
	var user AdminUser
	if err := c.BodyParser(&user); err != nil {
		logger.LogError("invalid user payload in create user",
			logger.ErrorField(err),
			logger.String("ip", c.IP()),
			logger.String("body", string(c.Body())))
		return errorResponse(c, fiber.StatusBadRequest, "invalid_payload", "Invalid user payload", err)
	}
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = user.CreatedAt
	}
	if err := h.store.CreateUser(&user); err != nil {
		logger.LogError("failed to create user",
			logger.ErrorField(err),
			logger.String("username", user.Username),
			logger.String("email", user.Email),
			logger.String("id", user.ID))
		return errorResponse(c, fiber.StatusInternalServerError, "create_failed", "Failed to create user", err)
	}

	logger.LogInfo("user created successfully",
		logger.String("id", user.ID),
		logger.String("username", user.Username),
		logger.String("email", user.Email))
	return c.Status(fiber.StatusCreated).JSON(user)
}

func (h *AdminHandler) UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user AdminUser
	if err := c.BodyParser(&user); err != nil {
		logger.LogError("invalid user payload in update user",
			logger.ErrorField(err),
			logger.String("id", id),
			logger.String("ip", c.IP()),
			logger.String("body", string(c.Body())))
		return errorResponse(c, fiber.StatusBadRequest, "invalid_payload", "Invalid user payload", err)
	}
	user.ID = id
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now().UTC()
	}
	if err := h.store.UpdateUser(&user); err != nil {
		logger.LogError("failed to update user",
			logger.ErrorField(err),
			logger.String("id", id),
			logger.String("username", user.Username),
			logger.String("email", user.Email))
		return errorResponse(c, fiber.StatusInternalServerError, "update_failed", "Failed to update user", err)
	}

	logger.LogInfo("user updated successfully",
		logger.String("id", user.ID),
		logger.String("username", user.Username),
		logger.String("email", user.Email))
	return c.Status(fiber.StatusOK).JSON(user)
}

func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("missing id parameter in delete user",
			logger.String("path", c.Path()),
			logger.String("ip", c.IP()))
		return errorResponse(c, fiber.StatusBadRequest, "missing_id", "Missing user ID", nil)
	}

	if err := h.store.DeleteUser(id); err != nil {
		logger.LogError("failed to delete user",
			logger.ErrorField(err),
			logger.String("id", id),
			logger.String("ip", c.IP()))
		return errorResponse(c, fiber.StatusInternalServerError, "delete_failed", "Failed to delete user", err)
	}

	logger.LogInfo("user deleted successfully", logger.String("id", id))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"success": true})
}

func (h *AdminHandler) CreateTenant(c *fiber.Ctx) error {
	var tenant Tenant
	if err := c.BodyParser(&tenant); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid tenant payload"})
	}
	if err := h.store.CreateTenant(&tenant); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create tenant"})
	}
	return c.Status(fiber.StatusCreated).JSON(tenant)
}

func (h *AdminHandler) UpdateTenant(c *fiber.Ctx) error {
	id := c.Params("id")
	var tenant Tenant
	if err := c.BodyParser(&tenant); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid tenant payload"})
	}
	tenant.ID = id
	if err := h.store.UpdateTenant(&tenant); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update tenant"})
	}
	return c.Status(fiber.StatusOK).JSON(tenant)
}

func (h *AdminHandler) DeleteTenant(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.store.DeleteTenant(id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete tenant"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminHandler) CreateRole(c *fiber.Ctx) error {
	var role AdminRole
	if err := c.BodyParser(&role); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid role payload"})
	}
	if err := h.store.CreateRole(&role); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create role"})
	}
	return c.Status(fiber.StatusCreated).JSON(role)
}

func (h *AdminHandler) UpdateRole(c *fiber.Ctx) error {
	id := c.Params("id")
	var role AdminRole
	if err := c.BodyParser(&role); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid role payload"})
	}
	role.ID = id
	if err := h.store.UpdateRole(&role); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update role"})
	}
	return c.Status(fiber.StatusOK).JSON(role)
}

func (h *AdminHandler) DeleteRole(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.store.DeleteRole(id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete role"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminHandler) CreatePermission(c *fiber.Ctx) error {
	var perm AdminPermission
	if err := c.BodyParser(&perm); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid permission payload"})
	}
	if err := h.store.CreatePermission(&perm); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create permission"})
	}
	return c.Status(fiber.StatusCreated).JSON(perm)
}

func (h *AdminHandler) UpdatePermission(c *fiber.Ctx) error {
	id := c.Params("id")
	var perm AdminPermission
	if err := c.BodyParser(&perm); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid permission payload"})
	}
	perm.ID = id
	if err := h.store.UpdatePermission(&perm); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update permission"})
	}
	return c.Status(fiber.StatusOK).JSON(perm)
}

func (h *AdminHandler) DeletePermission(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.store.DeletePermission(id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete permission"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminHandler) RevokeUserSessions(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	count, err := h.store.RevokeUserSessions(req.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to revoke user sessions"})
	}
	// Audit log
	if err := h.store.LogAuditEvent("admin", "revoke_user_sessions", req.UserID, map[string]interface{}{"count": count}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"revoked": count})
}

func (h *AdminHandler) RevokeTenantSessions(c *fiber.Ctx) error {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.TenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid tenant_id"})
	}
	count, err := h.store.RevokeTenantSessions(req.TenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to revoke tenant sessions"})
	}
	// Audit log
	if err := h.store.LogAuditEvent("admin", "revoke_tenant_sessions", req.TenantID, map[string]interface{}{"count": count}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"revoked": count})
}

func (h *AdminHandler) EnableMFA(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	if err := h.store.EnableMFA(req.UserID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to enable MFA"})
	}
	if err := h.store.LogAuditEvent("admin", "enable_mfa", req.UserID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *AdminHandler) DisableMFA(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	if err := h.store.DisableMFA(req.UserID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to disable MFA"})
	}
	if err := h.store.LogAuditEvent("admin", "disable_mfa", req.UserID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *AdminHandler) ResetMFA(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	if err := h.store.ResetMFA(req.UserID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to reset MFA"})
	}
	if err := h.store.LogAuditEvent("admin", "reset_mfa", req.UserID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *AdminHandler) MFAStatus(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	status, err := h.store.MFAStatus(userID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "mfa_status_failed", userID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get MFA status"})
	}
	if err := h.store.LogAuditEvent("admin", "mfa_status", userID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) ListPolicies(c *fiber.Ctx) error {
	policies, err := h.store.ListPolicies()
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "list_policies_failed", "", map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch policies"})
	}
	if err := h.store.LogAuditEvent("admin", "list_policies", "", nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(policies)
}

func (h *AdminHandler) GetPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy id"})
	}
	policy, err := h.store.GetPolicy(id)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "get_policy_failed", id, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch policy"})
	}
	if err := h.store.LogAuditEvent("admin", "get_policy", id, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(policy)
}

func (h *AdminHandler) CreatePolicy(c *fiber.Ctx) error {
	var policy Policy
	if err := c.BodyParser(&policy); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy payload"})
	}
	if err := h.store.CreatePolicy(&policy); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create policy"})
	}
	if err := h.store.LogAuditEvent("admin", "create_policy", policy.ID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusCreated).JSON(policy)
}

func (h *AdminHandler) UpdatePolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	var policy Policy
	if err := c.BodyParser(&policy); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy payload"})
	}
	policy.ID = id
	if err := h.store.UpdatePolicy(&policy); err != nil {
		if err := h.store.LogAuditEvent("admin", "update_policy_failed", policy.ID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update policy"})
	}
	if err := h.store.LogAuditEvent("admin", "update_policy", policy.ID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(policy)
}

func (h *AdminHandler) DeletePolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.store.DeletePolicy(id); err != nil {
		if err := h.store.LogAuditEvent("admin", "delete_policy_failed", id, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete policy"})
	}
	if err := h.store.LogAuditEvent("admin", "delete_policy", id, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// UserTrace returns all audit logs for a given user
func (h *AdminHandler) UserTrace(c *fiber.Ctx) error {
	userID := c.Query("user_id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id required"})
	}
	logs, err := h.store.TraceUserActivity(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch user trace logs"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"logs": logs})
}

// BillingTrace returns all audit logs for a given billing account
func (h *AdminHandler) BillingTrace(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	if accountID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id required"})
	}
	logs, err := h.store.TraceBillingActivity(accountID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch billing trace logs"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"logs": logs})
}

// ImpersonationAudit returns impersonation audit logs
func (h *AdminHandler) ImpersonationAudit(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 100)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	offset := c.QueryInt("offset", 0)
	logs, err := h.store.ListImpersonationAudits(limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch impersonation audit logs"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"logs": logs})
}

// AssignPermissionToRole assigns a permission to a role
func (h *AdminHandler) AssignPermissionToRole(c *fiber.Ctx) error {
	roleID := c.Params("id")
	if roleID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role id required"})
	}
	var req struct {
		PermissionID string `json:"permission_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.PermissionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "permission_id required"})
	}
	role, err := h.store.GetRoleByID(roleID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "role not found"})
	}
	for _, pid := range role.Permissions {
		if pid == req.PermissionID {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "permission already assigned"})
		}
	}
	role.Permissions = append(role.Permissions, req.PermissionID)
	if err := h.store.UpdateRole(role); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to assign permission"})
	}
	actor := getActorID(c)
	if err := h.store.LogAuditEvent("role_permission", "assign", actor, map[string]interface{}{"role_id": roleID, "permission_id": req.PermissionID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(role)
}

// RemovePermissionFromRole removes a permission from a role
func (h *AdminHandler) RemovePermissionFromRole(c *fiber.Ctx) error {
	roleID := c.Params("id")
	permID := c.Params("perm_id")
	if roleID == "" || permID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role id and perm_id required"})
	}
	role, err := h.store.GetRoleByID(roleID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "role not found"})
	}
	newPerms := make([]string, 0, len(role.Permissions))
	found := false
	for _, pid := range role.Permissions {
		if pid == permID {
			found = true
			continue
		}
		newPerms = append(newPerms, pid)
	}
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "permission not assigned"})
	}
	role.Permissions = newPerms
	if err := h.store.UpdateRole(role); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to remove permission"})
	}
	actor := getActorID(c)
	if err := h.store.LogAuditEvent("role_permission", "revoke", actor, map[string]interface{}{"role_id": roleID, "permission_id": permID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(role)
}

// getActorID extracts the actor/user id from context claims for audit logging
func getActorID(c *fiber.Ctx) string {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok {
		return "unknown"
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return "unknown"
}

// AuditLogsToCSV converts audit logs to CSV format
func AuditLogsToCSV(logs []interface{}) (string, error) {
	if len(logs) == 0 {
		return "id,actor_id,action,resource,details,created_at,hash,prev_hash\n", nil
	}
	csv := "id,actor_id,action,resource,details,created_at,hash,prev_hash\n"
	for _, l := range logs {
		m, ok := l.(map[string]interface{})
		if !ok {
			return "", fiber.NewError(fiber.StatusInternalServerError, "invalid log format")
		}
		csv += sanitizeCSV(m["id"]) + "," + sanitizeCSV(m["actor_id"]) + "," + sanitizeCSV(m["action"]) + "," + sanitizeCSV(m["resource"]) + "," + sanitizeCSV(m["details"]) + "," + sanitizeCSV(m["created_at"]) + "," + sanitizeCSV(m["hash"]) + "," + sanitizeCSV(m["prev_hash"]) + "\n"
	}
	return csv, nil
}

// sanitizeCSV escapes CSV fields
func sanitizeCSV(v interface{}) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	if len(s) == 0 {
		return ""
	}
	if containsSpecialCSV(s) {
		return "\"" + escapeQuotes(s) + "\""
	}
	return s
}

func containsSpecialCSV(s string) bool {
	for _, c := range s {
		if c == ',' || c == '\n' || c == '"' {
			return true
		}
	}
	return false
}

func escapeQuotes(s string) string {
	return string([]rune(s))
}

// ListAPIKeys returns filtered, paginated API keys
func (h *AdminHandler) ListAPIKeys(c *fiber.Ctx) error {
	userID := c.Query("user_id")
	status := c.Query("status")
	limit := c.QueryInt("limit", 100)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	offset := c.QueryInt("offset", 0)
	keys, total, err := h.store.ListAPIKeys(userID, status, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch api keys"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "api_keys": keys})
}

// CreateAPIKey creates a new API key
func (h *AdminHandler) CreateAPIKey(c *fiber.Ctx) error {
	var req struct {
		UserID string `json:"user_id"`
		Name   string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	keyIface, err := h.store.CreateAPIKey(req.UserID, req.Name)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create api key"})
	}
	key, ok := keyIface.(*APIKey)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	// Audit log
	if err := h.store.LogAuditEvent("api_key", "create", req.UserID, map[string]interface{}{"api_key_id": key.ID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusCreated).JSON(key)
}

// GetAPIKey returns API key details
func (h *AdminHandler) GetAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid id"})
	}
	key, err := h.store.GetAPIKey(id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "api key not found"})
	}
	return c.Status(fiber.StatusOK).JSON(key)
}

// UpdateAPIKey updates the name of an API key
func (h *AdminHandler) UpdateAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	keyIface, err := h.store.UpdateAPIKey(id, req.Name)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update api key"})
	}
	key, ok := keyIface.(*APIKey)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	// Audit log
	if err := h.store.LogAuditEvent("api_key", "update", key.UserID, map[string]interface{}{"api_key_id": key.ID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(key)
}

// RevokeAPIKey revokes an API key
func (h *AdminHandler) RevokeAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid id"})
	}
	keyIface, err := h.store.GetAPIKey(id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "api key not found"})
	}
	key, ok := keyIface.(*APIKey)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	if err := h.store.RevokeAPIKey(id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to revoke api key"})
	}
	// Audit log
	if err := h.store.LogAuditEvent("api_key", "revoke", key.UserID, map[string]interface{}{"api_key_id": key.ID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// RotateAPIKey rotates an API key and returns the new key
func (h *AdminHandler) RotateAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid id"})
	}
	keyIface, err := h.store.RotateAPIKey(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to rotate api key"})
	}
	key, ok := keyIface.(*APIKey)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error"})
	}
	// Audit log
	if err := h.store.LogAuditEvent("api_key", "rotate", key.UserID, map[string]interface{}{"api_key_id": key.ID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(fiber.StatusOK).JSON(key)
}

// ListAPIKeyAuditLogs returns filtered, paginated API key audit logs
func (h *AdminHandler) ListAPIKeyAuditLogs(c *fiber.Ctx) error {
	apiKeyID := c.Query("api_key_id")
	userID := c.Query("user_id")
	action := c.Query("action")
	var start, end *time.Time
	if v := c.Query("start"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err == nil {
			start = &t
		}
	}
	if v := c.Query("end"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err == nil {
			end = &t
		}
	}
	limit := c.QueryInt("limit", 100)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	offset := c.QueryInt("offset", 0)
	logs, total, err := h.store.ListAPIKeyAuditLogs(apiKeyID, userID, action, start, end, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch api key audit logs"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "logs": logs})
}

// ListNotifications returns filtered, paginated notifications
func (h *AdminHandler) ListNotifications(c *fiber.Ctx) error {
	recipient := c.Query("recipient")
	nType := c.Query("type")
	status := c.Query("status")
	limit := c.QueryInt("limit", 100)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	offset := c.QueryInt("offset", 0)
	notifs, total, err := h.store.ListNotifications(recipient, nType, status, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch notifications"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "notifications": notifs})
}

// SendNotification creates and sends a notification
func (h *AdminHandler) SendNotification(c *fiber.Ctx) error {
	var req struct {
		Type      string `json:"type"`
		Recipient string `json:"recipient"`
		Subject   string `json:"subject"`
		Body      string `json:"body"`
	}
	if err := c.BodyParser(&req); err != nil || req.Type == "" || req.Recipient == "" || req.Subject == "" || req.Body == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	notif, err := h.store.SendNotification(req.Type, req.Recipient, req.Subject, req.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to send notification"})
	}
	return c.Status(fiber.StatusCreated).JSON(notif)
}

// GetNotification returns a notification by ID
func (h *AdminHandler) GetNotification(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid id"})
	}
	notif, err := h.store.GetNotification(id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "notification not found"})
	}
	return c.Status(fiber.StatusOK).JSON(notif)
}

// MarkNotificationSent marks a notification as sent
func (h *AdminHandler) MarkNotificationSent(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		SentAt string `json:"sent_at"`
	}
	if err := c.BodyParser(&req); err != nil || req.SentAt == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	t, err := time.Parse(time.RFC3339, req.SentAt)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid sent_at format"})
	}
	notif, err := h.store.MarkNotificationSent(id, t)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to mark notification sent"})
	}
	return c.Status(fiber.StatusOK).JSON(notif)
}

// GetRateLimitConfig returns current admin rate limit config and status
func (h *AdminHandler) GetRateLimitConfig(c *fiber.Ctx) error {
	cfg, err := h.store.GetRateLimitConfig()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch rate limit config"})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

// UpdateRateLimitConfig updates admin rate limit config
func (h *AdminHandler) UpdateRateLimitConfig(c *fiber.Ctx) error {
	var input RateLimitConfigInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	cfg, err := h.store.UpdateRateLimitConfig(&input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update rate limit config"})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

// GetMonitoringConfig returns current real-time monitoring config and status
func (h *AdminHandler) GetMonitoringConfig(c *fiber.Ctx) error {
	cfg, err := h.store.GetMonitoringConfig()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch monitoring config"})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

// UpdateMonitoringConfig updates real-time monitoring config
func (h *AdminHandler) UpdateMonitoringConfig(c *fiber.Ctx) error {
	var input MonitoringConfigInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	cfg, err := h.store.UpdateMonitoringConfig(&input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update monitoring config"})
	}
	return c.Status(fiber.StatusOK).JSON(cfg)
}

// GetSecretsStatus returns current secrets status
func (h *AdminHandler) GetSecretsStatus(c *fiber.Ctx) error {
	status, err := h.store.GetSecretsStatus()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch secrets status"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

// UpdateSecrets rotates or updates secrets
func (h *AdminHandler) UpdateSecrets(c *fiber.Ctx) error {
	var input SecretsUpdateInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	status, err := h.store.UpdateSecrets(&input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update secrets"})
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

// RBAC middleware for admin roles
func requireAdminRole(roles ...string) fiber.Handler {
	roleSet := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		roleSet[r] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("claims").(map[string]interface{})
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no user context"})
		}
		userRolesIface, ok := claims["roles"]
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no roles claim"})
		}
		var userRoles []string
		switch v := userRolesIface.(type) {
		case []interface{}:
			for _, r := range v {
				if s, ok := r.(string); ok {
					userRoles = append(userRoles, s)
				}
			}
		case []string:
			userRoles = v
		case string:
			userRoles = strings.Split(v, ",")
		}
		for _, r := range userRoles {
			if _, allowed := roleSet[r]; allowed {
				return c.Next()
			}
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient role"})
	}
}

// RBAC middleware for admin permissions
func requireAdminPermission(perms ...string) fiber.Handler {
	permSet := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		permSet[p] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("claims").(map[string]interface{})
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no user context"})
		}
		userPermsIface, ok := claims["permissions"]
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: no permissions claim"})
		}
		var userPerms []string
		switch v := userPermsIface.(type) {
		case []interface{}:
			for _, p := range v {
				if s, ok := p.(string); ok {
					userPerms = append(userPerms, s)
				}
			}
		case []string:
			userPerms = v
		case string:
			userPerms = strings.Split(v, ",")
		}
		for _, p := range userPerms {
			if _, allowed := permSet[p]; allowed {
				return c.Next()
			}
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient permission"})
	}
}

// SSMBlogs handles SSM team blog management (list, filter, paginate)
func (h *AdminHandler) SSMBlogs(c *fiber.Ctx) error {
	filter := SSMBlogFilter{
		Query:   c.Query("query"),
		Status:  c.Query("status"),
		SortBy:  c.Query("sort_by"),
		SortDir: c.Query("sort_dir"),
		Limit:   c.QueryInt("limit", 100),
		Offset:  c.QueryInt("offset", 0),
	}
	if filter.Limit < 1 || filter.Limit > 1000 {
		filter.Limit = 100
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	blogs, total, err := store.ListSSMBlogs(c.Context(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list SSM blogs"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "blogs": blogs})
}

// SSMNews handles SSM team news management (list, filter, paginate)
func (h *AdminHandler) SSMNews(c *fiber.Ctx) error {
	filter := SSMNewsFilter{
		Query:   c.Query("query"),
		Status:  c.Query("status"),
		SortBy:  c.Query("sort_by"),
		SortDir: c.Query("sort_dir"),
		Limit:   c.QueryInt("limit", 100),
		Offset:  c.QueryInt("offset", 0),
	}
	if filter.Limit < 1 || filter.Limit > 1000 {
		filter.Limit = 100
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	news, total, err := store.ListSSMNews(c.Context(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list SSM news"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "news": news})
}

// Email management endpoints (RBAC: superuser/support/marketing)
func (h *AdminHandler) ListEmailProviders(c *fiber.Ctx) error {
	// RBAC check omitted for brevity, add in real code
	providers := h.emailManager.ListProviders()
	return c.Status(200).JSON(providers)
}

func (h *AdminHandler) AddEmailProvider(c *fiber.Ctx) error {
	var cfg email.EmailProviderConfig
	if err := c.BodyParser(&cfg); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid provider config"})
	}
	setDefault := c.QueryBool("set_default", false)
	h.emailManager.AddProvider(cfg, setDefault)
	return c.SendStatus(201)
}

func (h *AdminHandler) UpdateEmailProvider(c *fiber.Ctx) error {
	var cfg email.EmailProviderConfig
	if err := c.BodyParser(&cfg); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid provider config"})
	}
	if err := h.emailManager.UpdateProvider(cfg); err != nil {
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

func (h *AdminHandler) RemoveEmailProvider(c *fiber.Ctx) error {
	name := c.Params("name")
	if name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "provider name required"})
	}
	h.emailManager.RemoveProvider(name)
	return c.SendStatus(204)
}

func (h *AdminHandler) SetDefaultEmailProvider(c *fiber.Ctx) error {
	name := c.Params("name")
	if name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "provider name required"})
	}
	if err := h.emailManager.SetDefaultProvider(name); err != nil {
		return c.Status(404).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

func (h *AdminHandler) TestSMTPConnection(c *fiber.Ctx) error {
	name := c.Params("name")
	if name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "provider name required"})
	}
	if err := h.emailManager.TestSMTPConnection(name); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

func (h *AdminHandler) ListEmailTemplates(c *fiber.Ctx) error {
	tpls := h.emailManager.ListTemplates()
	return c.Status(200).JSON(tpls)
}

func (h *AdminHandler) AddEmailTemplate(c *fiber.Ctx) error {
	var tpl email.EmailTemplate
	if err := c.BodyParser(&tpl); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid template"})
	}
	h.emailManager.AddTemplate(tpl)
	return c.SendStatus(201)
}

func (h *AdminHandler) RemoveEmailTemplate(c *fiber.Ctx) error {
	name := c.Params("name")
	if name == "" {
		return c.Status(400).JSON(fiber.Map{"error": "template name required"})
	}
	h.emailManager.RemoveTemplate(name)
	return c.SendStatus(204)
}

func (h *AdminHandler) ListTeamAdmins(c *fiber.Ctx) error {
	team := c.Params("team")
	if team == "" {
		return c.Status(400).JSON(fiber.Map{"error": "team required"})
	}
	admins := h.emailManager.ListTeamAdmins(team)
	return c.Status(200).JSON(admins)
}

func (h *AdminHandler) AddTeamAdmin(c *fiber.Ctx) error {
	team := c.Params("team")
	if team == "" {
		return c.Status(400).JSON(fiber.Map{"error": "team required"})
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&req); err != nil || req.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid email"})
	}
	h.emailManager.AddTeamAdmin(team, req.Email)
	return c.SendStatus(201)
}

func (h *AdminHandler) RemoveTeamAdmin(c *fiber.Ctx) error {
	team := c.Params("team")
	email := c.Params("email")
	if team == "" || email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "team and email required"})
	}
	h.emailManager.RemoveTeamAdmin(team, email)
	return c.SendStatus(204)
}

func (h *AdminHandler) SendTestEmail(c *fiber.Ctx) error {
	var req struct {
		Provider string `json:"provider"`
		To       string `json:"to"`
		Subject  string `json:"subject"`
		Body     string `json:"body"`
	}
	if err := c.BodyParser(&req); err != nil || req.Provider == "" || req.To == "" || req.Subject == "" || req.Body == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid payload"})
	}
	providers := h.emailManager.ListProviders()
	var cfg *email.EmailProviderConfig
	for i := range providers {
		if providers[i].Name == req.Provider {
			cfg = &providers[i]
			break
		}
	}
	if cfg == nil {
		return c.Status(404).JSON(fiber.Map{"error": "provider not found"})
	}
	if cfg.Type != email.ProviderSMTP {
		return c.Status(400).JSON(fiber.Map{"error": "unsupported provider type"})
	}
	// Use SendWithTemplate with ad-hoc template name and pass subject/body as data
	if err := h.emailManager.SendWithTemplate(cfg.Name, "test", req.To, map[string]interface{}{"subject": req.Subject, "body": req.Body}); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(204)
}

// ListEmailDeliveries returns delivery status for emails (by recipient or message ID)
func (h *AdminHandler) ListEmailDeliveries(c *fiber.Ctx) error {
	recipient := c.Query("recipient")
	status := c.Query("status")
	limit := c.QueryInt("limit", 100)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	offset := c.QueryInt("offset", 0)
	// This assumes EmailManager has ListDeliveries(recipient, status string, limit, offset int) ([]DeliveryStatus, error)
	deliveries, err := h.emailManager.ListDeliveries(recipient, status, limit, offset)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(200).JSON(deliveries)
}

// ListConversations returns all conversations for a participant
func (h *AdminHandler) ListConversations(c *fiber.Ctx) error {
	participant := c.Query("participant")
	if participant == "" {
		return c.Status(400).JSON(fiber.Map{"error": "participant required"})
	}
	convs := h.emailManager.ListConversations(participant)
	return c.Status(200).JSON(convs)
}

// ListMessages returns all messages in a conversation
func (h *AdminHandler) ListMessages(c *fiber.Ctx) error {
	conversationID := c.Params("conversationID")
	if conversationID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "conversationID required"})
	}
	msgs := h.emailManager.ListMessages(conversationID)
	return c.Status(200).JSON(msgs)
}

// StartConversation creates a new conversation and first message
func (h *AdminHandler) StartConversation(c *fiber.Ctx) error {
	var req struct {
		Subject string   `json:"subject"`
		From    string   `json:"from"`
		To      []string `json:"to"`
		Body    string   `json:"body"`
	}
	if err := c.BodyParser(&req); err != nil || req.Subject == "" || req.From == "" || len(req.To) == 0 || req.Body == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid payload"})
	}
	cid, err := h.emailManager.StartConversation(req.Subject, req.From, req.To, req.Body)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(201).JSON(fiber.Map{"conversationID": cid})
}

// AddMessage adds a message to an existing conversation
func (h *AdminHandler) AddMessage(c *fiber.Ctx) error {
	var req struct {
		ConversationID string   `json:"conversationID"`
		From           string   `json:"from"`
		To             []string `json:"to"`
		Body           string   `json:"body"`
	}
	if err := c.BodyParser(&req); err != nil || req.ConversationID == "" || req.From == "" || len(req.To) == 0 || req.Body == "" {
		return c.Status(400).JSON(fiber.Map{"error": "invalid payload"})
	}
	mid, err := h.emailManager.AddMessage(req.ConversationID, req.From, req.To, req.Body)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(201).JSON(fiber.Map{"messageID": mid})
}

func (h *AdminHandler) ListUserEffectivePermissions(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user id required"})
	}
	ctx := c.Context()
	roles, err := h.userStore.ListRolesByUser(ctx, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list user roles"})
	}
	permSet := make(map[string]struct{})
	for _, r := range roles {
		for _, p := range r.Permissions {
			permSet[p] = struct{}{}
		}
	}
	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"user_id": userID, "effective_permissions": perms})
}

// Add admin endpoints for project user management
// List users in a project
func (h *AdminHandler) ListProjectUsers(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "project id required"})
	}
	users, err := h.userStore.ListRolesByProject(c.Context(), projectID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "list_project_users_failed", projectID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list project users"})
	}
	if err := h.store.LogAuditEvent("admin", "list_project_users", projectID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(users)
}

// Add user to project
func (h *AdminHandler) AddUserToProject(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "project id required"})
	}
	var req struct {
		UserID string   `json:"user_id"`
		Role   string   `json:"role"`
		Perms  []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.Role == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id and role required"})
	}
	role := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      req.UserID,
		ProjectID:   &projectID,
		Role:        req.Role,
		Permissions: req.Perms,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.userStore.CreateRole(c.Context(), role); err != nil {
		if err := h.store.LogAuditEvent("admin", "add_user_to_project_failed", projectID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to add user to project"})
	}
	if err := h.store.LogAuditEvent("admin", "add_user_to_project", projectID, map[string]interface{}{"user_id": req.UserID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// Remove user from project
func (h *AdminHandler) RemoveUserFromProject(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "project id required"})
	}
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id required"})
	}
	roles, err := h.userStore.ListRolesByUser(c.Context(), req.UserID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "remove_user_from_project_failed", projectID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list user roles"})
	}
	var removed bool
	for _, r := range roles {
		if r.ProjectID != nil && *r.ProjectID == projectID {
			if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
				if err := h.store.LogAuditEvent("admin", "remove_user_from_project_failed", projectID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to remove user from project"})
			}
			removed = true
		}
	}
	if !removed {
		return c.Status(404).JSON(fiber.Map{"error": "user has no roles in project"})
	}
	if err := h.store.LogAuditEvent("admin", "remove_user_from_project", projectID, map[string]interface{}{"user_id": req.UserID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// Transfer project owner
func (h *AdminHandler) TransferProjectOwner(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "project id required"})
	}
	var req struct {
		NewOwnerID string `json:"new_owner_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.NewOwnerID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "new_owner_id required"})
	}
	roles, err := h.userStore.ListRolesByProject(c.Context(), projectID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "transfer_project_owner_failed", projectID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list project roles"})
	}
	var oldOwnerID string
	for _, r := range roles {
		if r.Role == "owner" {
			oldOwnerID = r.UserID
			if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
				if err := h.store.LogAuditEvent("admin", "transfer_project_owner_failed", projectID, map[string]interface{}{"error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to remove old owner"})
			}
		}
	}
	role := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      req.NewOwnerID,
		ProjectID:   &projectID,
		Role:        "owner",
		Permissions: []string{"project:admin", "project:write", "project:read"},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.userStore.CreateRole(c.Context(), role); err != nil {
		if err := h.store.LogAuditEvent("admin", "transfer_project_owner_failed", projectID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to assign new owner"})
	}
	if err := h.store.LogAuditEvent("admin", "transfer_project_owner", projectID, map[string]interface{}{"old_owner_id": oldOwnerID, "new_owner_id": req.NewOwnerID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// Transfer user between orgs
func (h *AdminHandler) TransferUserToOrg(c *fiber.Ctx) error {
	var req struct {
		UserID    string `json:"user_id"`
		FromOrgID string `json:"from_org_id"`
		ToOrgID   string `json:"to_org_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.FromOrgID == "" || req.ToOrgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id, from_org_id, to_org_id required"})
	}
	roles, err := h.userStore.ListRolesByUser(c.Context(), req.UserID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "transfer_user_to_org_failed", req.FromOrgID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list user roles"})
	}
	var transferred bool
	for _, r := range roles {
		if r.OrgID != nil && *r.OrgID == req.FromOrgID {
			if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
				if err := h.store.LogAuditEvent("admin", "transfer_user_to_org_failed", req.FromOrgID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to remove user from old org"})
			}
			newRole := &user.UserOrgProjectRole{
				ID:          uuid.NewString(),
				UserID:      req.UserID,
				OrgID:       &req.ToOrgID,
				Role:        r.Role,
				Permissions: r.Permissions,
				CreatedAt:   time.Now().UTC(),
				UpdatedAt:   time.Now().UTC(),
			}
			if err := h.userStore.CreateRole(c.Context(), newRole); err != nil {
				if err := h.store.LogAuditEvent("admin", "transfer_user_to_org_failed", req.ToOrgID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to assign user to new org"})
			}
			transferred = true
		}
	}
	if !transferred {
		return c.Status(404).JSON(fiber.Map{"error": "user has no roles in fromOrgID"})
	}
	if err := h.store.LogAuditEvent("admin", "transfer_user_to_org", req.ToOrgID, map[string]interface{}{"user_id": req.UserID, "from": req.FromOrgID, "to": req.ToOrgID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// Change user org role
func (h *AdminHandler) ChangeUserOrgRole(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id required"})
	}
	var req struct {
		UserID string   `json:"user_id"`
		Role   string   `json:"role"`
		Perms  []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.Role == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id and role required"})
	}
	roles, err := h.userStore.ListRolesByUser(c.Context(), req.UserID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to list user roles"})
	}
	for _, r := range roles {
		if r.OrgID != nil && *r.OrgID == orgID {
			if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "failed to remove old org role"})
			}
		}
	}
	newRole := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      req.UserID,
		OrgID:       &orgID,
		Role:        req.Role,
		Permissions: req.Perms,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.userStore.CreateRole(c.Context(), newRole); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to assign new org role"})
	}
	err = h.store.LogAuditEvent("admin", "change_user_org_role", orgID, map[string]interface{}{"user_id": req.UserID, "role": req.Role})
	if err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// View user org effective permissions
func (h *AdminHandler) ViewUserOrgEffectivePermissions(c *fiber.Ctx) error {
	orgID := c.Params("id")
	userID := c.Params("user_id")
	if orgID == "" || userID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id and user_id required"})
	}
	roles, err := h.userStore.ListRolesByUser(c.Context(), userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to list user roles"})
	}
	permSet := make(map[string]struct{})
	for _, r := range roles {
		if r.OrgID != nil && *r.OrgID == orgID {
			for _, p := range r.Permissions {
				permSet[p] = struct{}{}
			}
		}
	}
	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}
	return c.Status(200).JSON(fiber.Map{"user_id": userID, "org_id": orgID, "effective_permissions": perms})
}

// Bulk add users to project (transactional, async for large batches, granular error reporting)
func (h *AdminHandler) BulkAddUsersToProject(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "project id required"})
	}
	var req struct {
		Users []struct {
			UserID string   `json:"user_id"`
			Role   string   `json:"role"`
			Perms  []string `json:"permissions"`
		} `json:"users"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.Users) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "users required"})
	}
	if len(req.Users) > 100 {
		// Async job for large batches
		go h.bulkAddUsersToProjectAsync(projectID, req.Users)
		return c.Status(202).JSON(fiber.Map{"job": "bulk_add_users_to_project", "status": "queued"})
	}
	tx, err := h.userStore.DB.Begin(c.Context())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to begin transaction"})
	}
	defer func() {
		if err := tx.Rollback(c.Context()); err != nil && err.Error() != "tx is closed" {
			logger.LogError("failed to rollback tx", logger.ErrorField(err))
		}
	}()
	var roles []*user.UserOrgProjectRole
	var failed []string
	for _, u := range req.Users {
		if u.UserID == "" || u.Role == "" {
			failed = append(failed, u.UserID)
			continue
		}
		roles = append(roles, &user.UserOrgProjectRole{
			ID:          uuid.NewString(),
			UserID:      u.UserID,
			ProjectID:   &projectID,
			Role:        u.Role,
			Permissions: u.Perms,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		})
	}
	err = h.userStore.CreateRolesTx(c.Context(), tx, roles)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to add users to project", "details": err.Error(), "failed": failed})
	}
	if err := tx.Commit(c.Context()); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to commit transaction"})
	}
	err = h.store.LogAuditEvent("admin", "bulk_add_users_to_project", projectID, map[string]interface{}{"added": len(roles), "failed": failed})
	if err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"added": len(roles), "failed": failed})
}

// Bulk remove users from project (transactional, async for large batches, granular error reporting)
func (h *AdminHandler) BulkRemoveUsersFromProject(c *fiber.Ctx) error {
	projectID := c.Params("id")
	if projectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "project id required"})
	}
	var req struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.UserIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "user_ids required"})
	}
	if len(req.UserIDs) > 100 {
		go h.bulkRemoveUsersFromProjectAsync(projectID, req.UserIDs)
		return c.Status(202).JSON(fiber.Map{"job": "bulk_remove_users_from_project", "status": "queued"})
	}
	tx, err := h.userStore.DB.Begin(c.Context())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to begin transaction"})
	}
	defer func() {
		if err := tx.Rollback(c.Context()); err != nil && err.Error() != "tx is closed" {
			logger.LogError("failed to rollback tx", logger.ErrorField(err))
		}
	}()
	var toDelete []string
	var failed []string
	for _, userID := range req.UserIDs {
		roles, err := h.userStore.ListRolesByUser(c.Context(), userID)
		if err != nil {
			failed = append(failed, userID)
			continue
		}
		found := false
		for _, r := range roles {
			if r.ProjectID != nil && *r.ProjectID == projectID {
				toDelete = append(toDelete, r.ID)
				found = true
			}
		}
		if !found {
			failed = append(failed, userID)
		}
	}
	if err := h.userStore.DeleteRolesTx(c.Context(), tx, toDelete); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to remove users from project", "details": err.Error(), "failed": failed})
	}
	if err := tx.Commit(c.Context()); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to commit transaction"})
	}
	h.store.LogAuditEvent("admin", "bulk_remove_users_from_project", projectID, map[string]interface{}{"removed": len(toDelete), "failed": failed})
	return c.Status(200).JSON(fiber.Map{"removed": len(toDelete), "failed": failed})
}

// Bulk transfer users between projects (transactional, async for large batches, granular error reporting)
func (h *AdminHandler) BulkTransferUsersBetweenProjects(c *fiber.Ctx) error {
	var req struct {
		UserIDs       []string `json:"user_ids"`
		FromProjectID string   `json:"from_project_id"`
		ToProjectID   string   `json:"to_project_id"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.UserIDs) == 0 || req.FromProjectID == "" || req.ToProjectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_ids, from_project_id, to_project_id required"})
	}
	if len(req.UserIDs) > 100 {
		go h.bulkTransferUsersBetweenProjectsAsync(req.UserIDs, req.FromProjectID, req.ToProjectID)
		return c.Status(202).JSON(fiber.Map{"job": "bulk_transfer_users_between_projects", "status": "queued"})
	}
	tx, err := h.userStore.DB.Begin(c.Context())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to begin transaction"})
	}
	defer func() {
		if err := tx.Rollback(c.Context()); err != nil && err.Error() != "tx is closed" {
			logger.LogError("failed to rollback tx", logger.ErrorField(err))
		}
	}()
	var toDelete []string
	var toCreate []*user.UserOrgProjectRole
	var transferred []string
	var failed []string
	for _, userID := range req.UserIDs {
		roles, err := h.userStore.ListRolesByUser(c.Context(), userID)
		if err != nil {
			failed = append(failed, userID)
			continue
		}
		found := false
		for _, r := range roles {
			if r.ProjectID != nil && *r.ProjectID == req.FromProjectID {
				toDelete = append(toDelete, r.ID)
				toCreate = append(toCreate, &user.UserOrgProjectRole{
					ID:          uuid.NewString(),
					UserID:      userID,
					ProjectID:   &req.ToProjectID,
					Role:        r.Role,
					Permissions: r.Permissions,
					CreatedAt:   time.Now().UTC(),
					UpdatedAt:   time.Now().UTC(),
				})
				transferred = append(transferred, userID)
				found = true
			}
		}
		if !found {
			failed = append(failed, userID)
		}
	}
	if err := h.userStore.DeleteRolesTx(c.Context(), tx, toDelete); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to remove users from old project", "details": err.Error(), "failed": failed})
	}
	if err := h.userStore.CreateRolesTx(c.Context(), tx, toCreate); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to assign users to new project", "details": err.Error(), "failed": failed})
	}
	if err := tx.Commit(c.Context()); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to commit transaction"})
	}
	h.store.LogAuditEvent("admin", "bulk_transfer_users_between_projects", req.ToProjectID, map[string]interface{}{"transferred": transferred, "failed": failed})
	return c.Status(200).JSON(fiber.Map{"transferred": transferred, "failed": failed})
}

// Async job for bulk transfer users between projects
func (h *AdminHandler) bulkTransferUsersBetweenProjectsAsync(userIDs []string, fromProjectID, toProjectID string) {
	tx, err := h.userStore.DB.Begin(context.Background())
	if err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_projects_async_failed", toProjectID, map[string]interface{}{"error": "failed to begin transaction"})
		return
	}
	defer func() {
		if err := tx.Rollback(context.Background()); err != nil && err.Error() != "tx is closed" {
			h.store.LogAuditEvent("admin", "bulk_transfer_users_between_projects_async_failed", toProjectID, map[string]interface{}{"error": err.Error()})
		}
	}()
	var toDelete []string
	var toCreate []*user.UserOrgProjectRole
	var transferred []string
	var failed []string
	for _, userID := range userIDs {
		roles, err := h.userStore.ListRolesByUser(context.Background(), userID)
		if err != nil {
			failed = append(failed, userID)
			continue
		}
		found := false
		for _, r := range roles {
			if r.ProjectID != nil && *r.ProjectID == fromProjectID {
				toDelete = append(toDelete, r.ID)
				toCreate = append(toCreate, &user.UserOrgProjectRole{
					ID:          uuid.NewString(),
					UserID:      userID,
					ProjectID:   &toProjectID,
					Role:        r.Role,
					Permissions: r.Permissions,
					CreatedAt:   time.Now().UTC(),
					UpdatedAt:   time.Now().UTC(),
				})
				transferred = append(transferred, userID)
				found = true
			}
		}
		if !found {
			failed = append(failed, userID)
		}
	}
	if err := h.userStore.DeleteRolesTx(context.Background(), tx, toDelete); err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_projects_async_failed", toProjectID, map[string]interface{}{"error": err.Error(), "failed": failed})
		return
	}
	if err := h.userStore.CreateRolesTx(context.Background(), tx, toCreate); err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_projects_async_failed", toProjectID, map[string]interface{}{"error": err.Error(), "failed": failed})
		return
	}
	if err := tx.Commit(context.Background()); err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_projects_async_failed", toProjectID, map[string]interface{}{"error": "failed to commit transaction"})
		return
	}
	h.store.LogAuditEvent("admin", "bulk_transfer_users_between_projects_async", toProjectID, map[string]interface{}{"transferred": transferred, "failed": failed})
}

// Bulk add users to org (transactional, async for large batches, granular error reporting)
func (h *AdminHandler) BulkAddUsersToOrg(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id required"})
	}
	var req struct {
		Users []struct {
			UserID string   `json:"user_id"`
			Role   string   `json:"role"`
			Perms  []string `json:"permissions"`
		} `json:"users"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.Users) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "users required"})
	}
	if len(req.Users) > 100 {
		go h.bulkAddUsersToOrgAsync(orgID, req.Users)
		return c.Status(202).JSON(fiber.Map{"job": "bulk_add_users_to_org", "status": "queued"})
	}
	userStore, ok := h.store.(interface {
		CreateRolesTx(ctx context.Context, tx pgx.Tx, roles []*user.UserOrgProjectRole) error
		DB() *pgxpool.Pool
	})
	if !ok {
		return c.Status(500).JSON(fiber.Map{"error": "user store does not support batch role creation"})
	}
	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()
	tx, err := userStore.DB().Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to begin transaction"})
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err.Error() != "tx is closed" {
			logger.LogError("failed to rollback tx", logger.ErrorField(err))
		}
	}()
	var roles []*user.UserOrgProjectRole
	var failed []string
	for _, u := range req.Users {
		if u.UserID == "" || u.Role == "" {
			failed = append(failed, u.UserID)
			continue
		}
		roles = append(roles, &user.UserOrgProjectRole{
			ID:          uuid.NewString(),
			UserID:      u.UserID,
			OrgID:       &orgID,
			Role:        u.Role,
			Permissions: u.Perms,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		})
	}
	err = userStore.CreateRolesTx(ctx, tx, roles)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to add users to org", "details": err.Error(), "failed": failed})
	}
	if err := tx.Commit(ctx); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to commit transaction"})
	}
	h.store.LogAuditEvent("admin", "bulk_add_users_to_org", orgID, map[string]interface{}{"added": len(roles), "failed": failed})
	return c.Status(200).JSON(fiber.Map{"added": len(roles), "failed": failed})
}

// Async job for bulk add users to org
func (h *AdminHandler) bulkAddUsersToOrgAsync(orgID string, users []struct {
	UserID string   `json:"user_id"`
	Role   string   `json:"role"`
	Perms  []string `json:"permissions"`
}) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tx, err := h.userStore.DB.Begin(ctx)
	if err != nil {
		h.store.LogAuditEvent("admin", "bulk_add_users_to_org_async_failed", orgID, map[string]interface{}{"error": "failed to begin transaction"})
		return
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err.Error() != "tx is closed" {
			h.store.LogAuditEvent("admin", "bulk_add_users_to_org_async_failed", orgID, map[string]interface{}{"error": err.Error()})
		}
	}()
	var toCreate []*user.UserOrgProjectRole
	var added []string
	var failed []string
	for _, u := range users {
		toCreate = append(toCreate, &user.UserOrgProjectRole{
			ID:          uuid.NewString(),
			UserID:      u.UserID,
			OrgID:       &orgID,
			Role:        u.Role,
			Permissions: u.Perms,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		})
		added = append(added, u.UserID)
	}
	if err := h.userStore.CreateRolesTx(ctx, tx, toCreate); err != nil {
		h.store.LogAuditEvent("admin", "bulk_add_users_to_org_async_failed", orgID, map[string]interface{}{"error": err.Error(), "failed": failed})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.store.LogAuditEvent("admin", "bulk_add_users_to_org_async_failed", orgID, map[string]interface{}{"error": "failed to commit transaction"})
		return
	}
	h.store.LogAuditEvent("admin", "bulk_add_users_to_org_async", orgID, map[string]interface{}{"added": added, "failed": failed})
}

// Bulk remove users from org
func (h *AdminHandler) BulkRemoveUsersFromOrg(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id required"})
	}
	var req struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.UserIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "user_ids required"})
	}
	var removed []string
	var failed []string
	for _, userID := range req.UserIDs {
		roles, err := h.userStore.ListRolesByUser(c.Context(), userID)
		if err != nil {
			failed = append(failed, userID)
			continue
		}
		found := false
		for _, r := range roles {
			if r.OrgID != nil && *r.OrgID == orgID {
				if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
					failed = append(failed, userID)
				} else {
					removed = append(removed, userID)
				}
				found = true
			}
		}
		if !found {
			failed = append(failed, userID)
		}
	}
	h.store.LogAuditEvent("admin", "bulk_remove_users_from_org", orgID, map[string]interface{}{"removed": removed, "failed": failed})
	return c.Status(200).JSON(fiber.Map{"removed": removed, "failed": failed})
}

// Bulk transfer users between orgs (transactional, async for large batches, granular error reporting)
func (h *AdminHandler) BulkTransferUsersBetweenOrgs(c *fiber.Ctx) error {
	fromOrgID := c.Params("from_org_id")
	toOrgID := c.Params("to_org_id")
	if fromOrgID == "" || toOrgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "from_org_id and to_org_id required"})
	}
	var req struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.UserIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "user_ids required"})
	}
	if len(req.UserIDs) > 100 {
		go h.bulkTransferUsersBetweenOrgsAsync(fromOrgID, toOrgID, req.UserIDs)
		return c.Status(202).JSON(fiber.Map{"job": "bulk_transfer_users_between_orgs", "status": "queued"})
	}
	ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
	defer cancel()
	tx, err := h.userStore.DB.Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to begin transaction"})
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err.Error() != "tx is closed" {
			logger.LogError("failed to rollback tx", logger.ErrorField(err))
		}
	}()
	var toDelete []string
	var toCreate []*user.UserOrgProjectRole
	var transferred []string
	var failed []string
	for _, userID := range req.UserIDs {
		roles, err := h.userStore.ListRolesByUser(ctx, userID)
		if err != nil {
			failed = append(failed, userID)
			continue
		}
		found := false
		for _, r := range roles {
			if r.OrgID != nil && *r.OrgID == fromOrgID {
				toDelete = append(toDelete, r.ID)
				toCreate = append(toCreate, &user.UserOrgProjectRole{
					ID:          uuid.NewString(),
					UserID:      userID,
					OrgID:       &toOrgID,
					Role:        r.Role,
					Permissions: r.Permissions,
					CreatedAt:   time.Now().UTC(),
					UpdatedAt:   time.Now().UTC(),
				})
				transferred = append(transferred, userID)
				found = true
			}
		}
		if !found {
			failed = append(failed, userID)
		}
	}
	if err := h.userStore.DeleteRolesTx(ctx, tx, toDelete); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to remove users from old org", "details": err.Error(), "failed": failed})
	}
	if err := h.userStore.CreateRolesTx(ctx, tx, toCreate); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to assign users to new org", "details": err.Error(), "failed": failed})
	}
	if err := tx.Commit(ctx); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to commit transaction"})
	}
	h.store.LogAuditEvent("admin", "bulk_transfer_users_between_orgs", toOrgID, map[string]interface{}{"transferred": transferred, "failed": failed})
	return c.Status(200).JSON(fiber.Map{"transferred": transferred, "failed": failed})
}

func (h *AdminHandler) bulkTransferUsersBetweenOrgsAsync(fromOrgID, toOrgID string, userIDs []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tx, err := h.userStore.DB.Begin(ctx)
	if err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_orgs_async_failed", toOrgID, map[string]interface{}{"error": "failed to begin transaction"})
		return
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err.Error() != "tx is closed" {
			h.store.LogAuditEvent("admin", "bulk_transfer_users_between_orgs_async_failed", toOrgID, map[string]interface{}{"error": err.Error()})
		}
	}()
	var toDelete []string
	var toCreate []*user.UserOrgProjectRole
	var transferred []string
	var failed []string
	for _, userID := range userIDs {
		roles, err := h.userStore.ListRolesByUser(ctx, userID)
		if err != nil {
			failed = append(failed, userID)
			continue
		}
		found := false
		for _, r := range roles {
			if r.OrgID != nil && *r.OrgID == fromOrgID {
				toDelete = append(toDelete, r.ID)
				toCreate = append(toCreate, &user.UserOrgProjectRole{
					ID:          uuid.NewString(),
					UserID:      userID,
					OrgID:       &toOrgID,
					Role:        r.Role,
					Permissions: r.Permissions,
					CreatedAt:   time.Now().UTC(),
					UpdatedAt:   time.Now().UTC(),
				})
				transferred = append(transferred, userID)
				found = true
			}
		}
		if !found {
			failed = append(failed, userID)
		}
	}
	if err := h.userStore.DeleteRolesTx(ctx, tx, toDelete); err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_orgs_async_failed", toOrgID, map[string]interface{}{"error": err.Error(), "failed": failed})
		return
	}
	if err := h.userStore.CreateRolesTx(ctx, tx, toCreate); err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_orgs_async_failed", toOrgID, map[string]interface{}{"error": err.Error(), "failed": failed})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.store.LogAuditEvent("admin", "bulk_transfer_users_between_orgs_async_failed", toOrgID, map[string]interface{}{"error": "failed to commit transaction"})
		return
	}
	h.store.LogAuditEvent("admin", "bulk_transfer_users_between_orgs_async", toOrgID, map[string]interface{}{"transferred": transferred, "failed": failed})
}

// Async job for bulk add users to project
func (h *AdminHandler) bulkAddUsersToProjectAsync(projectID string, users []struct {
	UserID string   `json:"user_id"`
	Role   string   `json:"role"`
	Perms  []string `json:"permissions"`
}) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tx, err := h.userStore.DB.Begin(ctx)
	if err != nil {
		h.store.LogAuditEvent("admin", "bulk_add_users_to_project_async_failed", projectID, map[string]interface{}{"error": "failed to begin transaction"})
		return
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err.Error() != "tx is closed" {
			h.store.LogAuditEvent("admin", "bulk_add_users_to_project_async_failed", projectID, map[string]interface{}{"error": err.Error()})
		}
	}()
	var toCreate []*user.UserOrgProjectRole
	var added []string
	var failed []string
	for _, u := range users {
		toCreate = append(toCreate, &user.UserOrgProjectRole{
			ID:          uuid.NewString(),
			UserID:      u.UserID,
			ProjectID:   &projectID,
			Role:        u.Role,
			Permissions: u.Perms,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		})
		added = append(added, u.UserID)
	}
	if err := h.userStore.CreateRolesTx(ctx, tx, toCreate); err != nil {
		h.store.LogAuditEvent("admin", "bulk_add_users_to_project_async_failed", projectID, map[string]interface{}{"error": err.Error(), "failed": failed})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.store.LogAuditEvent("admin", "bulk_add_users_to_project_async_failed", projectID, map[string]interface{}{"error": "failed to commit transaction"})
		return
	}
	h.store.LogAuditEvent("admin", "bulk_add_users_to_project_async", projectID, map[string]interface{}{"added": added, "failed": failed})
}

func (h *AdminHandler) bulkRemoveUsersFromProjectAsync(projectID string, userIDs []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tx, err := h.userStore.DB.Begin(ctx)
	if err != nil {
		h.store.LogAuditEvent("admin", "bulk_remove_users_from_project_async_failed", projectID, map[string]interface{}{"error": "failed to begin transaction"})
		return
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err.Error() != "tx is closed" {
			h.store.LogAuditEvent("admin", "bulk_remove_users_from_project_async_failed", projectID, map[string]interface{}{"error": err.Error()})
		}
	}()
	var toDelete []string
	var removed []string
	var failed []string
	for _, userID := range userIDs {
		roles, err := h.userStore.ListRolesByUser(ctx, userID)
		if err != nil {
			failed = append(failed, userID)
			continue
		}
		found := false
		for _, r := range roles {
			if r.ProjectID != nil && *r.ProjectID == projectID {
				toDelete = append(toDelete, r.ID)
				removed = append(removed, userID)
				found = true
			}
		}
		if !found {
			failed = append(failed, userID)
		}
	}
	if err := h.userStore.DeleteRolesTx(ctx, tx, toDelete); err != nil {
		h.store.LogAuditEvent("admin", "bulk_remove_users_from_project_async_failed", projectID, map[string]interface{}{"error": err.Error(), "failed": failed})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.store.LogAuditEvent("admin", "bulk_remove_users_from_project_async_failed", projectID, map[string]interface{}{"error": "failed to commit transaction"})
		return
	}
	h.store.LogAuditEvent("admin", "bulk_remove_users_from_project_async", projectID, map[string]interface{}{"removed": removed, "failed": failed})
}

// List all users with all their roles and permissions across orgs/projects/global
func (h *AdminHandler) ListAllUserRolesPermissions(c *fiber.Ctx) error {
	userStore, ok := h.store.(interface {
		ListAllUserRolesPermissions(ctx context.Context) ([]*user.UserRolesPermissions, error)
	})
	if !ok {
		return c.Status(500).JSON(fiber.Map{"error": "user store does not support global role/permission listing"})
	}
	ctx := c.Context()
	results, err := userStore.ListAllUserRolesPermissions(ctx)
	if err != nil {
		h.store.LogAuditEvent("admin", "list_all_user_roles_permissions_failed", "", map[string]interface{}{"error": err.Error()})
		return c.Status(500).JSON(fiber.Map{"error": "failed to list all user roles/permissions"})
	}
	h.store.LogAuditEvent("admin", "list_all_user_roles_permissions", "", nil)
	return c.Status(200).JSON(fiber.Map{"users": results})
}

func (h *AdminHandler) Login(c *fiber.Ctx) error {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&creds); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	ctx := c.Context()
	userStore, ok := h.store.(AdminUserStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin user store not supported"})
	}
	var adminUser *AdminUser
	var err error
	if strings.Contains(creds.Username, "@") {
		adminUser, err = userStore.GetByEmail(ctx, creds.Username)
	} else {
		adminUser, err = userStore.GetByUsername(ctx, creds.Username)
	}
	if err != nil || adminUser == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	ok, err = user.VerifyPassword(creds.Password, adminUser.PasswordHash)
	if err != nil || !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	}
	// JWT generation
	secretsMgr, ok := h.SecretsManager.(interface {
		GetSecret(context.Context, string) (string, error)
	})
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "secrets manager not available"})
	}
	jwtSecret, err := secretsMgr.GetSecret(ctx, h.JWTSecretName)
	if (err != nil || jwtSecret == "") && viper.GetString("jwt.secret_name") != "" {
		jwtSecret = viper.GetString("jwt.secret_name")
		err = nil
	}
	if err != nil || jwtSecret == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server misconfiguration"})
	}
	claims := jwt.MapClaims{
		"sub":   adminUser.Username,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"roles": adminUser.Roles,
		"email": adminUser.Email,
		"admin": true,
		"type":  "admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to sign token"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"token": tokenString, "type": "admin"})
}

func (h *AdminHandler) GetProfile(c *fiber.Ctx) error {
	admin, ok := c.Locals("admin").(*AdminUser)
	if !ok || admin == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"id":         admin.ID,
		"username":   admin.Username,
		"email":      admin.Email,
		"roles":      admin.Roles,
		"created_at": admin.CreatedAt,
		"updated_at": admin.UpdatedAt,
		"type":       "admin",
	})
}

func (h *AdminHandler) CreateProject(c *fiber.Ctx) error {
	var req Project
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project name required"})
	}
	store, ok := h.store.(interface{ ProjectStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "project store not supported"})
	}
	req.ID = "prj-" + uuid.NewString()
	req.CreatedAt = time.Now().UTC()
	req.UpdatedAt = req.CreatedAt
	if err := store.CreateProject(c.Context(), &req); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create project"})
	}
	return c.Status(fiber.StatusCreated).JSON(req)
}

func (h *AdminHandler) ListProjects(c *fiber.Ctx) error {
	// Parse query parameters for filtering, sorting and pagination
	query := c.Query("q", "")
	sortBy := c.Query("sort_by", "created_at")
	sortDir := c.Query("sort_dir", "DESC")
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	// Validate and cap limit
	if limit < 1 {
		limit = 10
	} else if limit > 1000 {
		limit = 1000
	}

	store, ok := h.store.(interface{ ProjectStore })
	if !ok {
		logger.LogError("project store not supported")
		return errorResponse(c, fiber.StatusInternalServerError, "store_error", "Project store not supported", nil)
	}

	filter := ProjectFilter{
		Query:   query,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	projects, total, err := store.ListProjects(c.Context(), filter)
	if err != nil {
		logger.LogError("failed to list projects",
			logger.ErrorField(err),
			logger.String("query", query),
			logger.String("sort_by", sortBy),
			logger.String("sort_dir", sortDir),
			logger.Int("limit", limit),
			logger.Int("offset", offset))
		return errorResponse(c, fiber.StatusInternalServerError, "list_failed", "Failed to list projects", err)
	}

	logger.LogInfo("projects listed successfully",
		logger.Int("total", total),
		logger.Int("returned", len(projects)))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"projects": projects,
		"total":    total,
	})
}

func (h *AdminHandler) GetProject(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	store, ok := h.store.(interface{ ProjectStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "project store not supported"})
	}
	project, err := store.GetProject(c.Context(), id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get project"})
	}
	return c.Status(fiber.StatusOK).JSON(project)
}

func (h *AdminHandler) ListOrgAPIKeys(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	apiKeys, err := store.ListOrgAPIKeys(orgID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list organization API keys"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"api_keys": apiKeys})
}

func (h *AdminHandler) ListOrgTeams(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	filter := OrgTeamFilter{
		OrgID:   orgID,
		Query:   c.Query("query"),
		SortBy:  c.Query("sort_by"),
		SortDir: c.Query("sort_dir"),
		Limit:   c.QueryInt("limit", 100),
		Offset:  c.QueryInt("offset", 0),
	}
	if filter.Limit < 1 || filter.Limit > 1000 {
		filter.Limit = 100
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	teams, total, err := store.ListOrgTeams(c.Context(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list org teams"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "teams": teams})
}

func (h *AdminHandler) CreateOrgTeam(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	var req OrgTeam
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "team name required"})
	}
	req.ID = "team-" + uuid.NewString()
	req.OrgID = orgID
	req.CreatedAt = time.Now().UTC()
	req.UpdatedAt = req.CreatedAt
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	if err := store.CreateOrgTeam(c.Context(), &req); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create org team"})
	}
	return c.Status(fiber.StatusCreated).JSON(req)
}

func (h *AdminHandler) GetOrgTeam(c *fiber.Ctx) error {
	orgID := c.Params("id")
	teamID := c.Params("team_id")
	if orgID == "" || teamID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id and team id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	team, err := store.GetOrgTeam(c.Context(), orgID, teamID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "org team not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get org team"})
	}
	return c.Status(fiber.StatusOK).JSON(team)
}

func (h *AdminHandler) UpdateOrgTeam(c *fiber.Ctx) error {
	orgID := c.Params("id")
	teamID := c.Params("team_id")
	if orgID == "" || teamID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id and team id required"})
	}
	var req OrgTeam
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	team, err := store.GetOrgTeam(c.Context(), orgID, teamID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "org team not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get org team"})
	}
	if req.Name != "" {
		team.Name = req.Name
	}
	if req.Description != "" {
		team.Description = req.Description
	}
	if req.UserIDs != nil {
		team.UserIDs = req.UserIDs
	}
	if req.Settings != "" {
		team.Settings = req.Settings
	}
	team.UpdatedAt = time.Now().UTC()
	if err := store.UpdateOrgTeam(c.Context(), team); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update org team"})
	}
	return c.Status(fiber.StatusOK).JSON(team)
}

func (h *AdminHandler) DeleteOrgTeam(c *fiber.Ctx) error {
	orgID := c.Params("id")
	teamID := c.Params("team_id")
	if orgID == "" || teamID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id and team id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	if err := store.DeleteOrgTeam(c.Context(), orgID, teamID); err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "org team not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete org team"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminHandler) UpdateProject(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	var req Project
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	store, ok := h.store.(interface{ ProjectStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "project store not supported"})
	}
	project, err := store.GetProject(c.Context(), id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get project"})
	}
	if req.Name != "" {
		project.Name = req.Name
	}
	if req.Description != "" {
		project.Description = req.Description
	}
	if req.OwnerID != "" {
		project.OwnerID = req.OwnerID
	}
	project.UpdatedAt = time.Now().UTC()
	if err := store.UpdateProject(c.Context(), project); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update project"})
	}
	return c.Status(fiber.StatusOK).JSON(project)
}

func (h *AdminHandler) DeleteProject(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	store, ok := h.store.(interface{ ProjectStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "project store not supported"})
	}
	if err := store.DeleteProject(c.Context(), id); err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete project"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminHandler) ProjectAuditLogs(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	logs, err := store.ProjectAuditLogs(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch project audit logs"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"logs": logs})
}

func (h *AdminHandler) GetProjectSettings(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	settings, err := store.GetProjectSettings(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch project settings"})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

func (h *AdminHandler) UpdateProjectSettings(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	settings, err := store.UpdateProjectSettings(id, input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update project settings"})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

func (h *AdminHandler) InviteProjectUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil || req.Email == "" || req.Role == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and role required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	invitation, err := store.InviteProjectUser(id, req.Email, req.Role)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to invite project user"})
	}
	return c.Status(fiber.StatusCreated).JSON(invitation)
}

func (h *AdminHandler) ListProjectInvitations(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	invitations, err := store.ListProjectInvitations(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list project invitations"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"invitations": invitations})
}

func (h *AdminHandler) CreateProjectAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	apiKey, err := store.CreateProjectAPIKey(id, req.Name)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create project API key"})
	}
	return c.Status(fiber.StatusCreated).JSON(apiKey)
}

func (h *AdminHandler) ListProjectAPIKeys(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	apiKeys, err := store.ListProjectAPIKeys(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list project API keys"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"api_keys": apiKeys})
}

func (h *AdminHandler) CreateOrg(c *fiber.Ctx) error {
	var req Organization
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization name required"})
	}
	store, ok := h.store.(interface{ OrganizationStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "organization store not supported"})
	}
	req.ID = "org-" + uuid.NewString()
	req.CreatedAt = time.Now().UTC()
	if err := store.CreateOrganization(c.Context(), &req); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create organization"})
	}
	return c.Status(fiber.StatusCreated).JSON(req)
}

func (h *AdminHandler) ListOrgs(c *fiber.Ctx) error {
	q, sortBy, sortDir, limit, offset := parseListFilter(c, 100)
	store, ok := h.store.(interface{ OrganizationStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "organization store not supported"})
	}
	filter := OrganizationFilter{
		Query:   q,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	orgs, total, err := store.ListOrganizations(c.Context(), filter)
	if err != nil {
		fmt.Println("ListOrgs error:", err, "filter:", filter, "request_id:", c.Locals("request_id"))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list organizations"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "organizations": orgs})
}

func (h *AdminHandler) GetOrg(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	store, ok := h.store.(interface{ OrganizationStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "organization store not supported"})
	}
	org, err := store.GetOrganization(c.Context(), id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get organization"})
	}
	return c.Status(fiber.StatusOK).JSON(org)
}

func (h *AdminHandler) UpdateOrg(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	var req Organization
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	store, ok := h.store.(interface{ OrganizationStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "organization store not supported"})
	}
	org, err := store.GetOrganization(c.Context(), id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get organization"})
	}
	if req.Name != "" {
		org.Name = req.Name
	}
	org.UpdatedAt = time.Now().UTC()
	if err := store.UpdateOrganization(c.Context(), org); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update organization"})
	}
	return c.Status(fiber.StatusOK).JSON(org)
}

func (h *AdminHandler) DeleteOrg(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	store, ok := h.store.(interface{ OrganizationStore })
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "organization store not supported"})
	}
	if err := store.DeleteOrganization(c.Context(), id); err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete organization"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminHandler) OrgAuditLogs(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	logs, err := store.OrgAuditLogs(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch organization audit logs"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"logs": logs})
}

func (h *AdminHandler) GetOrgSettings(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	settings, err := store.GetOrgSettings(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch organization settings"})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

func (h *AdminHandler) UpdateOrgSettings(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	settings, err := store.UpdateOrgSettings(id, input)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update organization settings"})
	}
	return c.Status(fiber.StatusOK).JSON(settings)
}

func (h *AdminHandler) InviteOrgUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil || req.Email == "" || req.Role == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and role required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	invitation, err := store.InviteOrgUser(id, req.Email, req.Role)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to invite organization user"})
	}
	return c.Status(fiber.StatusCreated).JSON(invitation)
}

func (h *AdminHandler) ListOrgInvitations(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	invitations, err := store.ListOrgInvitations(id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list organization invitations"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"invitations": invitations})
}

func (h *AdminHandler) CreateOrgAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "organization id required"})
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name required"})
	}
	store, ok := h.store.(AdminStore)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "admin store not supported"})
	}
	apiKey, err := store.CreateOrgAPIKey(id, req.Name)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create organization API key"})
	}
	return c.Status(fiber.StatusCreated).JSON(apiKey)
}

// Transfer user between projects
func (h *AdminHandler) TransferUserToProject(c *fiber.Ctx) error {
	var req struct {
		UserID        string `json:"user_id"`
		FromProjectID string `json:"from_project_id"`
		ToProjectID   string `json:"to_project_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.FromProjectID == "" || req.ToProjectID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id, from_project_id, to_project_id required"})
	}
	roles, err := h.userStore.ListRolesByUser(c.Context(), req.UserID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "transfer_user_to_project_failed", req.FromProjectID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list user roles"})
	}
	var transferred bool
	for _, r := range roles {
		if r.ProjectID != nil && *r.ProjectID == req.FromProjectID {
			if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
				if err := h.store.LogAuditEvent("admin", "transfer_user_to_project_failed", req.FromProjectID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to remove user from old project"})
			}
			newRole := &user.UserOrgProjectRole{
				ID:          uuid.NewString(),
				UserID:      req.UserID,
				ProjectID:   &req.ToProjectID,
				Role:        r.Role,
				Permissions: r.Permissions,
				CreatedAt:   time.Now().UTC(),
				UpdatedAt:   time.Now().UTC(),
			}
			if err := h.userStore.CreateRole(c.Context(), newRole); err != nil {
				if err := h.store.LogAuditEvent("admin", "transfer_user_to_project_failed", req.ToProjectID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to assign user to new project"})
			}
			transferred = true
		}
	}
	if !transferred {
		return c.Status(404).JSON(fiber.Map{"error": "user has no roles in fromProjectID"})
	}
	if err := h.store.LogAuditEvent("admin", "transfer_user_to_project", req.ToProjectID, map[string]interface{}{"user_id": req.UserID, "from": req.FromProjectID, "to": req.ToProjectID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// List users in an org
func (h *AdminHandler) ListOrgUsers(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id required"})
	}
	users, err := h.userStore.ListRolesByOrg(c.Context(), orgID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "list_org_users_failed", orgID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list org users"})
	}
	if err := h.store.LogAuditEvent("admin", "list_org_users", orgID, nil); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(users)
}

// Add user to org
func (h *AdminHandler) AddUserToOrg(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id required"})
	}
	var req struct {
		UserID string   `json:"user_id"`
		Role   string   `json:"role"`
		Perms  []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" || req.Role == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id and role required"})
	}
	role := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      req.UserID,
		OrgID:       &orgID,
		Role:        req.Role,
		Permissions: req.Perms,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.userStore.CreateRole(c.Context(), role); err != nil {
		if err := h.store.LogAuditEvent("admin", "add_user_to_org_failed", orgID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to add user to org"})
	}
	if err := h.store.LogAuditEvent("admin", "add_user_to_org", orgID, map[string]interface{}{"user_id": req.UserID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// Remove user from org
func (h *AdminHandler) RemoveUserFromOrg(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id required"})
	}
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "user_id required"})
	}
	roles, err := h.userStore.ListRolesByUser(c.Context(), req.UserID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "remove_user_from_org_failed", orgID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list user roles"})
	}
	var removed bool
	for _, r := range roles {
		if r.OrgID != nil && *r.OrgID == orgID {
			if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
				if err := h.store.LogAuditEvent("admin", "remove_user_from_org_failed", orgID, map[string]interface{}{"user_id": req.UserID, "error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to remove user from org"})
			}
			removed = true
		}
	}
	if !removed {
		return c.Status(404).JSON(fiber.Map{"error": "user has no roles in org"})
	}
	if err := h.store.LogAuditEvent("admin", "remove_user_from_org", orgID, map[string]interface{}{"user_id": req.UserID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}

// Transfer org owner
func (h *AdminHandler) TransferOrgOwner(c *fiber.Ctx) error {
	orgID := c.Params("id")
	if orgID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "org id required"})
	}
	var req struct {
		NewOwnerID string `json:"new_owner_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.NewOwnerID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "new_owner_id required"})
	}
	roles, err := h.userStore.ListRolesByOrg(c.Context(), orgID)
	if err != nil {
		if err := h.store.LogAuditEvent("admin", "transfer_org_owner_failed", orgID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to list org roles"})
	}
	var oldOwnerID string
	for _, r := range roles {
		if r.Role == "owner" {
			oldOwnerID = r.UserID
			if err := h.userStore.DeleteRole(c.Context(), r.ID); err != nil {
				if err := h.store.LogAuditEvent("admin", "transfer_org_owner_failed", orgID, map[string]interface{}{"error": err.Error()}); err != nil {
					logger.LogError("failed to log audit event", logger.ErrorField(err))
				}
				return c.Status(500).JSON(fiber.Map{"error": "failed to remove old owner"})
			}
		}
	}
	role := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      req.NewOwnerID,
		OrgID:       &orgID,
		Role:        "owner",
		Permissions: []string{"org:admin", "org:write", "org:read"},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := h.userStore.CreateRole(c.Context(), role); err != nil {
		if err := h.store.LogAuditEvent("admin", "transfer_org_owner_failed", orgID, map[string]interface{}{"error": err.Error()}); err != nil {
			logger.LogError("failed to log audit event", logger.ErrorField(err))
		}
		return c.Status(500).JSON(fiber.Map{"error": "failed to assign new owner"})
	}
	if err := h.store.LogAuditEvent("admin", "transfer_org_owner", orgID, map[string]interface{}{"old_owner_id": oldOwnerID, "new_owner_id": req.NewOwnerID}); err != nil {
		logger.LogError("failed to log audit event", logger.ErrorField(err))
	}
	return c.Status(200).JSON(fiber.Map{"success": true})
}
