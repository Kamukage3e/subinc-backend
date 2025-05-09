package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/spf13/viper"
)

// SecurityHeaders applies strict HTTP security headers using helmet with custom config
func SecurityHeaders() fiber.Handler {
	return helmet.New(helmet.Config{
		XSSProtection:             viper.GetString("XSS_PROTECTION"),
		ContentTypeNosniff:        viper.GetString("CONTENT_TYPE_NOSNIFF"),
		XFrameOptions:             viper.GetString("X_FRAME_OPTIONS"),
		ReferrerPolicy:            viper.GetString("REFERRER_POLICY"),
		CrossOriginResourcePolicy: viper.GetString("CROSS_ORIGIN_RESOURCE_POLICY"),
		CrossOriginOpenerPolicy:   viper.GetString("CROSS_ORIGIN_OPENER_POLICY"),
		CrossOriginEmbedderPolicy: viper.GetString("CROSS_ORIGIN_EMBEDDER_POLICY"),
		HSTSMaxAge:                viper.GetInt("HSTS_MAX_AGE"), // 2 years
		HSTSPreloadEnabled:        viper.GetBool("HSTS_PRELOAD_ENABLED"),
		// Add more as needed for your threat model
	})
}
