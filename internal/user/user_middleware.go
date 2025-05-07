package user

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
)

// DeviceSessionMiddleware enforces device/session status for all authenticated requests.
// If the device is revoked or the refresh token is expired, force logout and return 401.
func DeviceSessionMiddleware(store UserStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		refreshToken := c.Cookies("refresh_token")
		if refreshToken == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing refresh token"})
		}
		tok, err := store.GetRefreshToken(context.Background(), refreshToken)
		if err != nil || tok.Revoked || tok.ExpiresAt.Before(time.Now()) {
			c.ClearCookie("refresh_token")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired session"})
		}
		deviceStore, ok := store.(UserDeviceStore)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "device store not available"})
		}
		if tok.TokenID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid session"})
		}
		// Find device by refresh token id
		var device *UserDevice
		devices, err := deviceStore.ListDevicesByUserID(context.Background(), tok.UserID)
		if err == nil {
			for _, d := range devices {
				if d.RefreshTokenID == tok.TokenID {
					device = d
					break
				}
			}
		}
		if device == nil || device.Revoked {
			c.ClearCookie("refresh_token")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "device revoked"})
		}
		return c.Next()
	}
}
