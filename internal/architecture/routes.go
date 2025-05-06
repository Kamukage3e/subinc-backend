package architecture

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/cost/middleware"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

func (h *Handler) RegisterRoutes(router fiber.Router, secretsManager secrets.SecretsManager, jwtSecretName string) {
	arch := router.Group("/architecture")
	// Secure group for all sensitive endpoints
	secure := arch.Group("", middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
		SecretsManager: secretsManager,
		JWTSecretName:  jwtSecretName,
	}), middleware.RBACMiddleware("admin", "owner", "architect"))
	secure.Get("/docs", h.ListDocs)
	secure.Post("/docs/generate", h.GenerateDoc)
	secure.Get("/docs/:id", h.GetDoc)
	secure.Get("/diagrams", h.ListDiagrams)
	secure.Post("/diagrams/generate", h.GenerateDiagram)
	secure.Get("/diagrams/:id", h.GetDiagram)
	// Public endpoints
	arch.Get("/healthz", h.Healthz)
	arch.Get("/readyz", h.Readyz)
	arch.Get("/version", h.Version)
}
