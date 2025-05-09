package admin

import (
	"github.com/gofiber/fiber/v2"
)

func (h *AdminHandler) RegisterRoutes(router fiber.Router) {
	admin := router.Group("/admin")

	// === USER MANAGEMENT ===
	admin.Get("/users", h.ListUsers)
	admin.Post("/users", h.CreateUser)
	admin.Put("/users/:id", h.UpdateUser)
	admin.Delete("/users/:id", h.DeleteUser)
	admin.Get("/users/:id/effective-permissions", h.ListUserEffectivePermissions)
	admin.Get("/users/all-roles-permissions", h.ListAllUserRolesPermissions)
	admin.Get("/profile", h.GetProfile)

	// === TENANT MANAGEMENT ===
	admin.Get("/tenants", h.ListTenants)
	admin.Post("/tenants", h.CreateTenant)
	admin.Put("/tenants/:id", h.UpdateTenant)
	admin.Delete("/tenants/:id", h.DeleteTenant)

	// === ROLE & PERMISSION MANAGEMENT ===
	admin.Get("/roles", h.ListRoles)
	admin.Post("/roles", h.CreateRole)
	admin.Put("/roles/:id", h.UpdateRole)
	admin.Delete("/roles/:id", h.DeleteRole)
	admin.Get("/permissions", h.ListPermissions)
	admin.Post("/permissions", h.CreatePermission)
	admin.Put("/permissions/:id", h.UpdatePermission)
	admin.Delete("/permissions/:id", h.DeletePermission)
	admin.Post("/roles/:id/permissions", h.AssignPermissionToRole)
	admin.Delete("/roles/:id/permissions/:perm_id", h.RemovePermissionFromRole)

	// === SESSION & MFA ===
	admin.Get("/sessions", h.ListSessions)
	admin.Post("/sessions/revoke/user", h.RevokeUserSessions)
	admin.Post("/sessions/revoke/tenant", h.RevokeTenantSessions)
	admin.Post("/mfa/enable", h.EnableMFA)
	admin.Post("/mfa/disable", h.DisableMFA)
	admin.Post("/mfa/reset", h.ResetMFA)
	admin.Get("/mfa/status/:user_id", h.MFAStatus)

	// === AUDIT & SECURITY ===
	admin.Get("/audit", h.ListAuditLogs)
	admin.Get("/audit/anomaly", h.AuditAnomalies)
	admin.Get("/support/impersonation-audit", h.ImpersonationAudit)
	admin.Get("/support/user-trace", h.UserTrace)
	admin.Get("/support/billing-trace", h.BillingTrace)
	admin.Get("/security/health", h.SystemHealth)
	admin.Get("/abuse", h.AbuseDetection)
	admin.Get("/alerts", h.Alerts)

	// === RBAC/ABAC & SUPPORT TOOLS ===
	admin.Get("/rbac", h.RBACStatus)
	admin.Get("/support-tools", requireAdminRole(RoleSupport), requireAdminPermission(PermSupportViewTickets), h.SupportTools)
	admin.Post("/impersonate", h.ImpersonateUser)
	admin.Post("/stepup", h.StepUpAuth)
	admin.Get("/delegated-admin", h.DelegatedAdminStatus)
	admin.Get("/scim", h.SCIMStatus)

	// === RATE LIMITS ===
	admin.Get("/rate-limits", h.GetRateLimitConfig)
	admin.Patch("/rate-limits", h.UpdateRateLimitConfig)

	// === SECRETS MANAGEMENT ===
	admin.Get("/secrets", h.GetSecretsStatus)
	admin.Patch("/secrets", h.UpdateSecrets)

	// === SYSTEM CONFIG & MAINTENANCE ===
	admin.Get("/system/config", h.SystemConfig)
	admin.Get("/system/flags", h.ListFeatureFlags)
	admin.Post("/system/flags", h.CreateFeatureFlag)
	admin.Patch("/system/flags", h.UpdateFeatureFlag)
	admin.Delete("/system/flags", h.DeleteFeatureFlag)
	admin.Get("/system/maintenance", h.GetMaintenanceMode)
	admin.Patch("/system/maintenance", h.SetMaintenanceMode)

	// === MONITORING ===
	admin.Get("/monitoring", h.GetMonitoringConfig)
	admin.Patch("/monitoring", h.UpdateMonitoringConfig)

	// === API KEYS ===
	admin.Get("/api-keys", h.ListAPIKeys)
	admin.Post("/api-keys", h.CreateAPIKey)
	admin.Get("/api-keys/:id", h.GetAPIKey)
	admin.Put("/api-keys/:id", h.UpdateAPIKey)
	admin.Delete("/api-keys/:id", h.RevokeAPIKey)
	admin.Post("/api-keys/:id/rotate", h.RotateAPIKey)
	admin.Get("/api-keys/audit", h.ListAPIKeyAuditLogs)

	// === NOTIFICATIONS ===
	admin.Get("/notifications", h.ListNotifications)
	admin.Post("/notifications", h.SendNotification)
	admin.Get("/notifications/:id", h.GetNotification)
	admin.Patch("/notifications/:id", h.MarkNotificationSent)

	// === MARKETING & SSM ===
	admin.Get("/marketing-tools", requireAdminRole(RoleMarketing), requireAdminPermission(PermMarketingViewReports), h.ListFeatureFlags)
	admin.Get("/ssm/blogs", requireAdminRole(RoleSSM), requireAdminPermission(PermSSMManageBlogs), h.SSMBlogs)
	admin.Get("/ssm/news", requireAdminRole(RoleSSM), requireAdminPermission(PermSSMManageNews), h.SSMNews)

	// === EMAIL MANAGEMENT ===
	admin.Get("/email/providers", requireAdminRole(RoleSupport, RoleMarketing), h.ListEmailProviders)
	admin.Post("/email/providers", requireAdminRole(RoleSupport, RoleMarketing), h.AddEmailProvider)
	admin.Put("/email/providers", requireAdminRole(RoleSupport, RoleMarketing), h.UpdateEmailProvider)
	admin.Delete("/email/providers/:name", requireAdminRole(RoleSupport, RoleMarketing), h.RemoveEmailProvider)
	admin.Patch("/email/providers/:name/default", requireAdminRole(RoleSupport, RoleMarketing), h.SetDefaultEmailProvider)
	admin.Post("/email/providers/:name/test", requireAdminRole(RoleSupport, RoleMarketing), h.TestSMTPConnection)
	admin.Get("/email/templates", requireAdminRole(RoleSupport, RoleMarketing), h.ListEmailTemplates)
	admin.Post("/email/templates", requireAdminRole(RoleSupport, RoleMarketing), h.AddEmailTemplate)
	admin.Delete("/email/templates/:name", requireAdminRole(RoleSupport, RoleMarketing), h.RemoveEmailTemplate)
	admin.Get("/email/team/:team/admins", requireAdminRole(RoleSupport, RoleMarketing), h.ListTeamAdmins)
	admin.Post("/email/team/:team/admins", requireAdminRole(RoleSupport, RoleMarketing), h.AddTeamAdmin)
	admin.Delete("/email/team/:team/admins/:email", requireAdminRole(RoleSupport, RoleMarketing), h.RemoveTeamAdmin)
	admin.Post("/email/test", requireAdminRole(RoleSupport, RoleMarketing), h.SendTestEmail)
	admin.Get("/email/deliveries", requireAdminRole(RoleSupport, RoleMarketing), h.ListEmailDeliveries)
	admin.Get("/email/conversations", requireAdminRole(RoleSupport, RoleMarketing), h.ListConversations)
	admin.Get("/email/conversations/:conversationID/messages", requireAdminRole(RoleSupport, RoleMarketing), h.ListMessages)
	admin.Post("/email/conversations", requireAdminRole(RoleSupport, RoleMarketing), h.StartConversation)
	admin.Post("/email/conversations/:conversationID/messages", requireAdminRole(RoleSupport, RoleMarketing), h.AddMessage)

	// === POLICY MANAGEMENT ===
	admin.Get("/policies", h.ListPolicies)
	admin.Get("/policies/:id", h.GetPolicy)
	admin.Post("/policies", h.CreatePolicy)
	admin.Put("/policies/:id", h.UpdatePolicy)
	admin.Delete("/policies/:id", h.DeletePolicy)

	// === PROJECT MANAGEMENT ===
	admin.Post("/projects", h.CreateProject)
	admin.Get("/projects", h.ListProjects)
	admin.Get("/projects/:id", h.GetProject)
	admin.Put("/projects/:id", h.UpdateProject)
	admin.Delete("/projects/:id", h.DeleteProject)
	admin.Get("/projects/:id/users", h.ListProjectUsers)
	admin.Post("/projects/:id/users", h.AddUserToProject)
	admin.Delete("/projects/:id/users", h.RemoveUserFromProject)
	admin.Patch("/projects/:id/transfer-owner", h.TransferProjectOwner)
	admin.Patch("/projects/transfer-user", h.TransferUserToProject)
	admin.Post("/projects/:id/users/bulk-add", h.BulkAddUsersToProject)
	admin.Post("/projects/:id/users/bulk-remove", h.BulkRemoveUsersFromProject)
	admin.Post("/projects/users/bulk-transfer", h.BulkTransferUsersBetweenProjects)
	admin.Get("/projects/:id/users/:user_id/effective-permissions", h.ViewUserOrgEffectivePermissions)
	admin.Get("/projects/:id/audit", h.ProjectAuditLogs)
	admin.Get("/projects/:id/settings", h.GetProjectSettings)
	admin.Patch("/projects/:id/settings", h.UpdateProjectSettings)
	admin.Post("/projects/:id/invitations", h.InviteProjectUser)
	admin.Get("/projects/:id/invitations", h.ListProjectInvitations)
	admin.Post("/projects/:id/api-keys", h.CreateProjectAPIKey)
	admin.Get("/projects/:id/api-keys", h.ListProjectAPIKeys)
	admin.Post("/projects/:id/deactivate", h.DeactivateProject)
	admin.Post("/projects/:id/reactivate", h.ReactivateProject)
	admin.Delete("/projects/:id/purge", h.PurgeProject)
	admin.Get("/projects/:id/roles", h.ListProjectRoles)
	admin.Post("/projects/:id/roles", h.CreateProjectRole)
	admin.Put("/projects/:id/roles/:role_id", h.UpdateProjectRole)
	admin.Delete("/projects/:id/roles/:role_id", h.DeleteProjectRole)
	admin.Get("/projects/:id/usage", h.GetProjectUsage)
	admin.Get("/projects/:id/feature-flags", h.GetProjectFeatureFlags)
	admin.Patch("/projects/:id/feature-flags", h.UpdateProjectFeatureFlags)
	admin.Get("/projects/:id/webhooks", h.ListProjectWebhooks)
	admin.Post("/projects/:id/webhooks", h.CreateProjectWebhook)
	admin.Delete("/projects/:id/webhooks/:webhook_id", h.DeleteProjectWebhook)
	admin.Get("/projects/:id/secrets", h.ListProjectSecrets)
	admin.Post("/projects/:id/secrets", h.CreateProjectSecret)
	admin.Delete("/projects/:id/secrets/:secret_id", h.DeleteProjectSecret)
	admin.Get("/projects/:id/events", h.ListProjectEvents)

	// === ORG MANAGEMENT ===
	admin.Post("/orgs", h.CreateOrg)
	admin.Get("/orgs", h.ListOrgs)
	admin.Get("/orgs/:id", h.GetOrg)
	admin.Put("/orgs/:id", h.UpdateOrg)
	admin.Delete("/orgs/:id", h.DeleteOrg)
	admin.Get("/orgs/:id/audit", h.OrgAuditLogs)
	admin.Get("/orgs/:id/settings", h.GetOrgSettings)
	admin.Patch("/orgs/:id/settings", h.UpdateOrgSettings)
	admin.Post("/orgs/:id/invitations", h.InviteOrgUser)
	admin.Get("/orgs/:id/invitations", h.ListOrgInvitations)
	admin.Post("/orgs/:id/api-keys", h.CreateOrgAPIKey)
	admin.Get("/orgs/:id/api-keys", h.ListOrgAPIKeys)
	admin.Get("/orgs/:id/teams", h.ListOrgTeams)
	admin.Post("/orgs/:id/teams", h.CreateOrgTeam)
	admin.Get("/orgs/:id/teams/:team_id", h.GetOrgTeam)
	admin.Put("/orgs/:id/teams/:team_id", h.UpdateOrgTeam)
	admin.Delete("/orgs/:id/teams/:team_id", h.DeleteOrgTeam)
	admin.Patch("/orgs/:id/teams/:team_id/transfer-owner", h.TransferOrgOwner)
	admin.Delete("/orgs/:id/teams/:team_id/users/:user_id", h.RemoveUserFromOrg)
	admin.Post("/orgs/:id/teams/:team_id/users/bulk-add", h.BulkAddUsersToOrg)
	admin.Post("/orgs/:id/teams/:team_id/users/bulk-remove", h.BulkRemoveUsersFromOrg)
	admin.Post("/orgs/teams/bulk-transfer", h.BulkTransferUsersBetweenOrgs)
	admin.Get("/projects/:id/users/:user_id/effective-permissions", h.ViewUserOrgEffectivePermissions)
	admin.Get("/orgs/:id/users", h.ListOrgUsers)
	admin.Post("/orgs/:id/users", h.AddUserToOrg)
	admin.Delete("/orgs/:id/users", h.RemoveUserFromOrg)
	admin.Patch("/orgs/:id/transfer-owner", h.TransferOrgOwner)
	admin.Patch("/orgs/transfer-user", h.TransferUserToOrg)
	admin.Post("/orgs/:id/users/bulk-add", h.BulkAddUsersToOrg)
	admin.Post("/orgs/:id/users/bulk-remove", h.BulkRemoveUsersFromOrg)
	admin.Post("/orgs/bulk-transfer", h.BulkTransferUsersBetweenOrgs)
	admin.Patch("/orgs/:id/users/:user_id/role", h.ChangeUserOrgRole)
	admin.Get("/orgs/:id/users/:user_id/effective-permissions", h.ViewUserOrgEffectivePermissions)
	admin.Post("/orgs/:id/deactivate", h.DeactivateOrg)
	admin.Post("/orgs/:id/reactivate", h.ReactivateOrg)
	admin.Delete("/orgs/:id/purge", h.PurgeOrg)
	admin.Get("/orgs/:id/roles", h.ListOrgRoles)
	admin.Post("/orgs/:id/roles", h.CreateOrgRole)
	admin.Put("/orgs/:id/roles/:role_id", h.UpdateOrgRole)
	admin.Delete("/orgs/:id/roles/:role_id", h.DeleteOrgRole)
	admin.Get("/orgs/:id/usage", h.GetOrgUsage)
	admin.Get("/orgs/:id/feature-flags", h.GetOrgFeatureFlags)
	admin.Patch("/orgs/:id/feature-flags", h.UpdateOrgFeatureFlags)
	admin.Get("/orgs/:id/webhooks", h.ListOrgWebhooks)
	admin.Post("/orgs/:id/webhooks", h.CreateOrgWebhook)
	admin.Delete("/orgs/:id/webhooks/:webhook_id", h.DeleteOrgWebhook)
	admin.Get("/orgs/:id/secrets", h.ListOrgSecrets)
	admin.Post("/orgs/:id/secrets", h.CreateOrgSecret)
	admin.Delete("/orgs/:id/secrets/:secret_id", h.DeleteOrgSecret)
	admin.Get("/orgs/:id/events", h.ListOrgEvents)

	// === STUBS ===
	admin.Get("/metrics", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
			"error": "Not implemented",
			"path":  c.Path(),
		})
	})
	admin.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
			"error": "Not implemented",
			"path":  c.Path(),
		})
	})
}

func RegisterRoutes(router fiber.Router, handler *AdminHandler) {
	handler.RegisterRoutes(router)
}
