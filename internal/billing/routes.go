package billing

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/api"
)

func RegisterRoutes(router fiber.Router, handler *api.BillingHandler) {
	handler.RegisterBillingRoutes(router)
}
