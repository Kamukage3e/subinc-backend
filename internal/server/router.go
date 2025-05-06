package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/architecture"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
	// Add other handler imports as needed (user, tenant, admin, etc)
)

// SetupRouter centralizes all route registration for the microservice.
// This enforces modular, SaaS-grade routing boundaries and testability.
func SetupRouter(apiPrefix string, db *pgxpool.Pool, secretsManager secrets.SecretsManager, jwtSecretName string) *fiber.App {
	app := fiber.New()

	// Create API group for all routes
	apiGroup := app.Group(apiPrefix)

	// Architecture Docs & Diagrams
	archRepo := architecture.NewPostgresRepository(db)
	archService := architecture.NewService(archRepo)
	archHandler := architecture.NewHandler(archService, *logger.NewProduction())
	archHandler.RegisterRoutes(apiGroup.Group("/architecture"), secretsManager, jwtSecretName)

	return app
}
