package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// NewServer creates and configures a Fiber app with secure, production-ready defaults.
func NewServer(redisClient *redis.Client, pgPool *pgxpool.Pool) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:               "Subinc Cost Management Microservice",
		ServerHeader:          "Fiber",
		DisableStartupMessage: true,
	})
	// CORS: allow only trusted origins (adjust as needed for prod)
	app.Use(cors.New(cors.Config{
		AllowOrigins: "https://yourdomain.com,https://admin.yourdomain.com",
		AllowHeaders: "Authorization,Content-Type",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
	}))
	// Secure headers
	app.Use(helmet.New())
	// Rate limiting (prod defaults)
	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 60 * 1000 * 1, // 1 minute
	}))
	RegisterHealthRoutes(app, redisClient, pgPool)
	// Use only production-grade repositories and queues
	// TODO: Wire up production repositories, queues, and services here
	return app
}

// RegisterHealthRoutes registers health and readiness endpoints.
func RegisterHealthRoutes(app *fiber.App, redisClient *redis.Client, pgPool *pgxpool.Pool) {
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
	})

	app.Get("/healthz/redis", func(c *fiber.Ctx) error {
		err := RedisHealthCheck(c.Context(), redisClient)
		if err != nil {
			return c.Status(503).JSON(fiber.Map{"status": "unhealthy", "error": err.Error()})
		}
		return c.Status(200).JSON(fiber.Map{"status": "ok"})
	})

	app.Get("/healthz/postgres", func(c *fiber.Ctx) error {
		err := PostgresHealthCheck(c.Context(), pgPool)
		if err != nil {
			return c.Status(503).JSON(fiber.Map{"status": "unhealthy", "error": err.Error()})
		}
		return c.Status(200).JSON(fiber.Map{"status": "ok"})
	})
}
