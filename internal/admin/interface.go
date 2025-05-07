package admin

import (
	"context"
	"time"
)

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
	FeatureFlags() ([]interface{}, error)
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
	ListOrgTeams(ctx context.Context, filter OrgTeamFilter) ([]*OrgTeam, int, error)
	CreateOrgTeam(ctx context.Context, team *OrgTeam) error
	GetOrgTeam(ctx context.Context, orgID, teamID string) (*OrgTeam, error)
	UpdateOrgTeam(ctx context.Context, team *OrgTeam) error
	DeleteOrgTeam(ctx context.Context, orgID, teamID string) error
	ListSSMBlogs(ctx context.Context, filter SSMBlogFilter) ([]*SSMBlog, int, error)
	CreateSSMBlog(ctx context.Context, blog *SSMBlog) error
	GetSSMBlog(ctx context.Context, id string) (*SSMBlog, error)
	UpdateSSMBlog(ctx context.Context, blog *SSMBlog) error
	DeleteSSMBlog(ctx context.Context, id string) error
	ListSSMNews(ctx context.Context, filter SSMNewsFilter) ([]*SSMNews, int, error)
	CreateSSMNews(ctx context.Context, news *SSMNews) error
	GetSSMNews(ctx context.Context, id string) (*SSMNews, error)
	UpdateSSMNews(ctx context.Context, news *SSMNews) error
	DeleteSSMNews(ctx context.Context, id string) error
	// --- Project/org admin methods for handler ---
	ProjectAuditLogs(projectID string) ([]interface{}, error)
	GetProjectSettings(projectID string) (map[string]interface{}, error)
	UpdateProjectSettings(projectID string, settings map[string]interface{}) (map[string]interface{}, error)
	InviteProjectUser(projectID, email, role string) (interface{}, error)
	ListProjectInvitations(projectID string) ([]interface{}, error)
	CreateProjectAPIKey(projectID, name string) (interface{}, error)
	ListProjectAPIKeys(projectID string) ([]*APIKey, error)
	OrgAuditLogs(orgID string) ([]interface{}, error)
	GetOrgSettings(orgID string) (map[string]interface{}, error)
	UpdateOrgSettings(orgID string, settings map[string]interface{}) (map[string]interface{}, error)
	InviteOrgUser(orgID, email, role string) (interface{}, error)
	ListOrgInvitations(orgID string) ([]interface{}, error)
	CreateOrgAPIKey(orgID, name string) (interface{}, error)
	ListOrgAPIKeys(orgID string) ([]*APIKey, error)
}

// AdminUserStore defines storage for admin users.
type AdminUserStore interface {
	GetByUsername(ctx context.Context, username string) (*AdminUser, error)
	GetByEmail(ctx context.Context, email string) (*AdminUser, error)
	GetByID(ctx context.Context, id string) (*AdminUser, error)
	Create(ctx context.Context, u *AdminUser) error
	Update(ctx context.Context, u *AdminUser) error
	Delete(ctx context.Context, id string) error
}

// AdminRoleStore defines storage for admin roles.
type AdminRoleStore interface {
	GetByName(ctx context.Context, name string) (*AdminRole, error)
	GetByID(ctx context.Context, id string) (*AdminRole, error)
	Create(ctx context.Context, r *AdminRole) error
	Update(ctx context.Context, r *AdminRole) error
	Delete(ctx context.Context, id string) error
}

// AdminPermissionStore defines storage for admin permissions.
type AdminPermissionStore interface {
	GetByName(ctx context.Context, name string) (*AdminPermission, error)
	GetByID(ctx context.Context, id string) (*AdminPermission, error)
	Create(ctx context.Context, p *AdminPermission) error
	Update(ctx context.Context, p *AdminPermission) error
	Delete(ctx context.Context, id string) error
}

type ProjectStore interface {
	CreateProject(ctx context.Context, p *Project) error
	GetProject(ctx context.Context, id string) (*Project, error)
	UpdateProject(ctx context.Context, p *Project) error
	DeleteProject(ctx context.Context, id string) error
	ListProjects(ctx context.Context, filter ProjectFilter) ([]*Project, int, error)
}
type OrganizationStore interface {
	CreateOrganization(ctx context.Context, o *Organization) error
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	UpdateOrganization(ctx context.Context, o *Organization) error
	DeleteOrganization(ctx context.Context, id string) error
	ListOrganizations(ctx context.Context, filter OrganizationFilter) ([]*Organization, int, error)
}
