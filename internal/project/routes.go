package project

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterProjectRoutes(app *fiber.App, handler *Handler) {
	api := app.Group("/api")
	handler.RegisterRoutes(api)
}
