package project

import (
	"github.com/gofiber/fiber/v2"
)

func RegisterProjectRoutes(app *fiber.App, apiPrefix string, handler *Handler) {
	api := app.Group(apiPrefix)
	handler.RegisterRoutes(api)
}
