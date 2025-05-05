package admin

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// AdminStore defines the interface for admin data access
// Must be implemented by any admin storage backend
// All methods must be production-ready and secure

type AdminStore interface {
	ListUsers() ([]interface{}, error)
	ListTenants() ([]interface{}, error)
	ListAuditLogs() ([]interface{}, error)
	ListRoles() ([]interface{}, error)
	ListPermissions() ([]interface{}, error)
	BillingSummary() (interface{}, error)
	SystemHealth() (interface{}, error)
	ListSessions() ([]interface{}, error)
	ImpersonateUser(string) (interface{}, error)
	SupportTools() (interface{}, error)
	RBACStatus() (interface{}, error)
	StepUpAuth(string) (interface{}, error)
	DelegatedAdminStatus() (interface{}, error)
	SCIMStatus() (interface{}, error)
	AuditAnomalies() (interface{}, error)
	RateLimits() (interface{}, error)
	AbuseDetection() (interface{}, error)
	Alerts() (interface{}, error)
	SecretsStatus() (interface{}, error)
	SystemConfig() (interface{}, error)
	FeatureFlags() (interface{}, error)
	MaintenanceMode() (interface{}, error)
	RealTimeMonitoring() (interface{}, error)
	CreateUser(user *AdminUser) error
	UpdateUser(user *AdminUser) error
	DeleteUser(id string) error
	CreateTenant(tenant *Tenant) error
	UpdateTenant(tenant *Tenant) error
	DeleteTenant(id string) error
	CreateRole(role *AdminRole) error
	UpdateRole(role *AdminRole) error
	DeleteRole(id string) error
	CreatePermission(perm *AdminPermission) error
	UpdatePermission(perm *AdminPermission) error
	DeletePermission(id string) error
	RevokeUserSessions(userID string) (int, error)
	RevokeTenantSessions(tenantID string) (int, error)
	LogAuditEvent(eventType, action, userID string, details map[string]interface{}) error
	EnableMFA(userID string) error
	DisableMFA(userID string) error
	ResetMFA(userID string) error
	MFAStatus(userID string) (interface{}, error)
	ListPolicies() ([]interface{}, error)
	GetPolicy(id string) (interface{}, error)
	CreatePolicy(policy *Policy) error
	UpdatePolicy(policy *Policy) error
	DeletePolicy(id string) error
	SearchAuditLogs(filter AuditLogFilter) ([]interface{}, int, error)
	SearchUsers(filter UserFilter) ([]interface{}, int, error)
	SearchTenants(filter TenantFilter) ([]interface{}, int, error)
	SearchRoles(filter RoleFilter) ([]interface{}, int, error)
	SearchPermissions(filter PermissionFilter) ([]interface{}, int, error)
	TraceUserActivity(userID string) ([]interface{}, error)
	TraceBillingActivity(accountID string) ([]interface{}, error)
	ListImpersonationAudits(limit, offset int) ([]interface{}, error)
	GetRoleByID(id string) (*AdminRole, error)
	ListAPIKeys(userID, status string, limit, offset int) ([]interface{}, int, error)
	CreateAPIKey(userID, name string) (interface{}, error)
	GetAPIKey(id string) (interface{}, error)
	UpdateAPIKey(id, name string) (interface{}, error)
	RevokeAPIKey(id string) error
	RotateAPIKey(id string) (interface{}, error)
	ListAPIKeyAuditLogs(apiKeyID, userID, action string, start, end *time.Time, limit, offset int) ([]interface{}, int, error)
	ListNotifications(recipient, nType, status string, limit, offset int) ([]interface{}, int, error)
	SendNotification(nType, recipient, subject, body string) (interface{}, error)
	GetNotification(id string) (interface{}, error)
	MarkNotificationSent(id string, sentAt time.Time) (interface{}, error)
	GetRateLimitConfig() (interface{}, error)
	UpdateRateLimitConfig(input *RateLimitConfigInput) (interface{}, error)
	GetMaintenanceMode() (interface{}, error)
	SetMaintenanceMode(maintenance bool) (interface{}, error)
	GetMonitoringConfig() (interface{}, error)
	UpdateMonitoringConfig(input *MonitoringConfigInput) (interface{}, error)
	GetSecretsStatus() (interface{}, error)
	UpdateSecrets(input *SecretsUpdateInput) (interface{}, error)
	ListFeatureFlags() ([]interface{}, error)
	CreateFeatureFlag(input *FeatureFlagInput) (interface{}, error)
	UpdateFeatureFlag(input *FeatureFlagInput) (interface{}, error)
	DeleteFeatureFlag(flag string) error
}

// Only production-grade AdminStore implementations are supported. No in-memory or dev/test stores.

// AdminHandler handles admin-related endpoints
// Modular, SaaS-grade, handler-based routing
// All endpoints must be production-ready and secure

type AdminHandler struct {
	store AdminStore
}

func NewHandler(store AdminStore) *AdminHandler {
	return &AdminHandler{store: store}
}

func (h *AdminHandler) RegisterRoutes(router fiber.Router, apiPrefix string) {
	admin := router.Group(apiPrefix + "/admin")

	admin.Get("/users", h.ListUsers)
	admin.Get("/tenants", h.ListTenants)
	admin.Get("/audit", h.ListAuditLogs)
	admin.Get("/roles", h.ListRoles)
	admin.Get("/permissions", h.ListPermissions)
	admin.Get("/billing", h.BillingSummary)
	admin.Get("/security/health", h.SystemHealth)
	admin.Get("/sessions", h.ListSessions)
	admin.Post("/impersonate", h.ImpersonateUser)
	admin.Get("/support/tools", h.SupportTools)
	admin.Get("/rbac", h.RBACStatus)
	admin.Post("/stepup", h.StepUpAuth)
	admin.Get("/delegated-admin", h.DelegatedAdminStatus)
	admin.Get("/scim", h.SCIMStatus)
	admin.Get("/audit/anomaly", h.AuditAnomalies)
	admin.Get("/rate-limits", h.GetRateLimitConfig)
	admin.Patch("/rate-limits", h.UpdateRateLimitConfig)
	admin.Get("/abuse", h.AbuseDetection)
	admin.Get("/alerts", h.Alerts)
	admin.Get("/secrets", h.GetSecretsStatus)
	admin.Patch("/secrets", h.UpdateSecrets)
	admin.Get("/system/config", h.SystemConfig)
	admin.Get("/system/flags", h.ListFeatureFlags)
	admin.Post("/system/flags", h.CreateFeatureFlag)
	admin.Patch("/system/flags", h.UpdateFeatureFlag)
	admin.Delete("/system/flags", h.DeleteFeatureFlag)
	admin.Get("/system/maintenance", h.GetMaintenanceMode)
	admin.Patch("/system/maintenance", h.SetMaintenanceMode)
	admin.Get("/monitoring", h.GetMonitoringConfig)
	admin.Patch("/monitoring", h.UpdateMonitoringConfig)
	admin.Post("/users", h.CreateUser)
	admin.Put("/users/:id", h.UpdateUser)
	admin.Delete("/users/:id", h.DeleteUser)
	admin.Post("/tenants", h.CreateTenant)
	admin.Put("/tenants/:id", h.UpdateTenant)
	admin.Delete("/tenants/:id", h.DeleteTenant)
	admin.Post("/roles", h.CreateRole)
	admin.Put("/roles/:id", h.UpdateRole)
	admin.Delete("/roles/:id", h.DeleteRole)
	admin.Post("/permissions", h.CreatePermission)
	admin.Put("/permissions/:id", h.UpdatePermission)
	admin.Delete("/permissions/:id", h.DeletePermission)
	admin.Post("/sessions/revoke/user", h.RevokeUserSessions)
	admin.Post("/sessions/revoke/tenant", h.RevokeTenantSessions)
	admin.Post("/mfa/enable", h.EnableMFA)
	admin.Post("/mfa/disable", h.DisableMFA)
	admin.Post("/mfa/reset", h.ResetMFA)
	admin.Get("/mfa/status/:user_id", h.MFAStatus)
	admin.Get("/policies", h.ListPolicies)
	admin.Get("/policies/:id", h.GetPolicy)
	admin.Post("/policies", h.CreatePolicy)
	admin.Put("/policies/:id", h.UpdatePolicy)
	admin.Delete("/policies/:id", h.DeletePolicy)
	admin.Get("/support/user-trace", h.UserTrace)
	admin.Get("/support/billing-trace", h.BillingTrace)
	admin.Get("/support/impersonation-audit", h.ImpersonationAudit)
	admin.Post("/roles/:id/permissions", h.AssignPermissionToRole)
	admin.Delete("/roles/:id/permissions/:perm_id", h.RemovePermissionFromRole)
	admin.Get("/api-keys", h.ListAPIKeys)
	admin.Post("/api-keys", h.CreateAPIKey)
	admin.Get("/api-keys/:id", h.GetAPIKey)
	admin.Put("/api-keys/:id", h.UpdateAPIKey)
	admin.Delete("/api-keys/:id", h.RevokeAPIKey)
	admin.Post("/api-keys/:id/rotate", h.RotateAPIKey)
	admin.Get("/api-keys/audit", h.ListAPIKeyAuditLogs)
	admin.Get("/notifications", h.ListNotifications)
	admin.Post("/notifications", h.SendNotification)
	admin.Get("/notifications/:id", h.GetNotification)
	admin.Patch("/notifications/:id", h.MarkNotificationSent)
	// Add more admin endpoints as needed
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
	q, sortBy, sortDir, limit, offset := parseListFilter(c, 100)
	filter := UserFilter{
		Query:   q,
		Role:    c.Query("role"),
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	users, total, err := h.store.SearchUsers(filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch users"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "users": users})
}

func (h *AdminHandler) ListTenants(c *fiber.Ctx) error {
	q, sortBy, sortDir, limit, offset := parseListFilter(c, 100)
	filter := TenantFilter{
		Query:   q,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	tenants, total, err := h.store.SearchTenants(filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch tenants"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "tenants": tenants})
}

func (h *AdminHandler) ListRoles(c *fiber.Ctx) error {
	q, sortBy, sortDir, limit, offset := parseListFilter(c, 100)
	filter := RoleFilter{
		Query:   q,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	roles, total, err := h.store.SearchRoles(filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch roles"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "roles": roles})
}

func (h *AdminHandler) ListPermissions(c *fiber.Ctx) error {
	q, sortBy, sortDir, limit, offset := parseListFilter(c, 100)
	filter := PermissionFilter{
		Query:   q,
		SortBy:  sortBy,
		SortDir: sortDir,
		Limit:   limit,
		Offset:  offset,
	}
	perms, total, err := h.store.SearchPermissions(filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch permissions"})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"total": total, "permissions": perms})
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

func (h *AdminHandler) CreateUser(c *fiber.Ctx) error {
	var user AdminUser
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user payload"})
	}
	if err := h.store.CreateUser(&user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create user"})
	}
	return c.Status(fiber.StatusCreated).JSON(user)
}

func (h *AdminHandler) UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user AdminUser
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user payload"})
	}
	user.ID = id
	if err := h.store.UpdateUser(&user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update user"})
	}
	return c.Status(fiber.StatusOK).JSON(user)
}

func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.store.DeleteUser(id); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete user"})
	}
	return c.SendStatus(fiber.StatusNoContent)
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
	h.store.LogAuditEvent("admin", "revoke_user_sessions", req.UserID, map[string]interface{}{"count": count})
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
	h.store.LogAuditEvent("admin", "revoke_tenant_sessions", req.TenantID, map[string]interface{}{"count": count})
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
	h.store.LogAuditEvent("admin", "enable_mfa", req.UserID, nil)
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
	h.store.LogAuditEvent("admin", "disable_mfa", req.UserID, nil)
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
	h.store.LogAuditEvent("admin", "reset_mfa", req.UserID, nil)
	return c.SendStatus(fiber.StatusOK)
}

func (h *AdminHandler) MFAStatus(c *fiber.Ctx) error {
	userID := c.Params("user_id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}
	status, err := h.store.MFAStatus(userID)
	if err != nil {
		h.store.LogAuditEvent("admin", "mfa_status_failed", userID, map[string]interface{}{"error": err.Error()})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get MFA status"})
	}
	h.store.LogAuditEvent("admin", "mfa_status", userID, nil)
	return c.Status(fiber.StatusOK).JSON(status)
}

func (h *AdminHandler) ListPolicies(c *fiber.Ctx) error {
	policies, err := h.store.ListPolicies()
	if err != nil {
		h.store.LogAuditEvent("admin", "list_policies_failed", "", map[string]interface{}{"error": err.Error()})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch policies"})
	}
	h.store.LogAuditEvent("admin", "list_policies", "", nil)
	return c.Status(fiber.StatusOK).JSON(policies)
}

func (h *AdminHandler) GetPolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy id"})
	}
	policy, err := h.store.GetPolicy(id)
	if err != nil {
		h.store.LogAuditEvent("admin", "get_policy_failed", id, map[string]interface{}{"error": err.Error()})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch policy"})
	}
	h.store.LogAuditEvent("admin", "get_policy", id, nil)
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
	h.store.LogAuditEvent("admin", "create_policy", policy.ID, nil)
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
		h.store.LogAuditEvent("admin", "update_policy_failed", policy.ID, map[string]interface{}{"error": err.Error()})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update policy"})
	}
	h.store.LogAuditEvent("admin", "update_policy", policy.ID, nil)
	return c.Status(fiber.StatusOK).JSON(policy)
}

func (h *AdminHandler) DeletePolicy(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.store.DeletePolicy(id); err != nil {
		h.store.LogAuditEvent("admin", "delete_policy_failed", id, map[string]interface{}{"error": err.Error()})
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete policy"})
	}
	h.store.LogAuditEvent("admin", "delete_policy", id, nil)
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
	return c.Status(fiber.StatusOK).JSON(role)
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
	h.store.LogAuditEvent("api_key", "create", req.UserID, map[string]interface{}{"api_key_id": key.ID})
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
	h.store.LogAuditEvent("api_key", "update", key.UserID, map[string]interface{}{"api_key_id": key.ID})
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
	h.store.LogAuditEvent("api_key", "revoke", key.UserID, map[string]interface{}{"api_key_id": key.ID})
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
	h.store.LogAuditEvent("api_key", "rotate", key.UserID, map[string]interface{}{"api_key_id": key.ID})
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
