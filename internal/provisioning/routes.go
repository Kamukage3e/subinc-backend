package provisioning

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/provisioning/terraform"
	provisioningtypes "github.com/subinc/subinc-backend/internal/provisioningtypes"
)

type Deps struct {
	TerraformProvisioner *terraform.TerraformProvisioner
}

func RegisterRoutes(router fiber.Router, deps Deps) {
	provGroup := router.Group("/provisioning")
	provGroup.Post("/terraform", func(c *fiber.Ctx) error {
		var req provisioningtypes.ProvisionRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		status, err := deps.TerraformProvisioner.Provision(c.Context(), &req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusAccepted).JSON(status)
	})
	provGroup.Get("/terraform/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")
		status, err := deps.TerraformProvisioner.GetStatus(c.Context(), id)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(status)
	})
	provGroup.Get("/terraform", func(c *fiber.Ctx) error {
		tenantID := c.Query("tenant_id")
		orgID := c.Query("org_id")
		projectID := c.Query("project_id")
		statuses, err := deps.TerraformProvisioner.List(c.Context(), tenantID, orgID, projectID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(statuses)
	})
	provGroup.Post("/terraform/:id/cancel", func(c *fiber.Ctx) error {
		id := c.Params("id")
		if err := deps.TerraformProvisioner.Cancel(c.Context(), id); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"status": "cancelled"})
	})
}
