package server_config

import (
	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// RegisterAdminServerConfigRoutes registers admin API routes for server config management.
func RegisterAdminServerConfigRoutes(router fiber.Router, handler *Handler, jwtSecret string) {
	cfg := router.Group(
		"/server-config",
		security_management.OIDCMiddleware(jwtSecret),
	)
	cfg.Get("/list", handler.ListConfig)
	cfg.Get("/get/:key", handler.GetConfig)
	cfg.Post("/set", handler.SetConfig)
	cfg.Get("/history/:key", handler.ConfigHistory)
}
