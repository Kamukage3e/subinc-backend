package organization_management

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterAdminOrganizationRoutes(router fiber.Router, handler *OrganizationAdminHandler) {
	org := router.Group("/organization-management")

	org.Post("/organizations/create", handler.CreateOrganization)
	org.Put("/organizations/update/:id", handler.UpdateOrganization)
	org.Delete("/organizations/delete/:id", handler.DeleteOrganization)
	org.Get("/organizations/get/:id", handler.GetOrganization)
	org.Get("/organizations/list", handler.ListOrganizations)

	org.Post("/members/add", handler.AddMember)
	org.Put("/members/update/:id", handler.UpdateMember)
	org.Delete("/members/remove/:id", handler.RemoveMember)
	org.Get("/members/get/:id", handler.GetMember)
	org.Get("/members/list", handler.ListMembers)
	org.Get("/members/search", handler.ListMembers)

	org.Post("/invites/create", handler.CreateInvite)
	org.Post("/invites/accept", handler.AcceptInvite)
	org.Delete("/invites/revoke/:id", handler.RevokeInvite)
	org.Get("/invites/list", handler.ListInvites)
	org.Get("/invites/search", handler.ListInvites)

	org.Post("/domains/add", handler.AddDomain)
	org.Put("/domains/verify/:id", handler.VerifyDomain)
	org.Delete("/domains/remove/:id", handler.RemoveDomain)
	org.Get("/domains/list", handler.ListDomains)

	org.Get("/settings/get", handler.GetSettings)
	org.Put("/settings/update", handler.UpdateSettings)

	org.Post("/audit-logs/create", handler.CreateAuditLog)
	org.Get("/audit-logs/list", handler.ListAuditLogs)
}
