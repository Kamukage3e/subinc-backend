package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// RateLimitMiddleware limits requests to 100 per minute per user (by sub claim or IP)
// For real SaaS, use Redis or distributed store for rate limiting
var rateLimitStore = struct {
	mu    sync.Mutex
	users map[string][]time.Time
}{users: make(map[string][]time.Time)}

func RateLimitMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := ""
		if claims := UserFromContext(c); claims != nil {
			if sub, ok := claims["sub"].(string); ok {
				userID = sub
			}
		}
		if userID == "" {
			userID = c.IP()
		}
		now := time.Now()
		cutoff := now.Add(-1 * time.Minute)
		rateLimitStore.mu.Lock()
		times := rateLimitStore.users[userID]
		// Remove old timestamps
		var filtered []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) >= 100 {
			rateLimitStore.mu.Unlock()
			return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{"error": "rate limit exceeded"})
		}
		filtered = append(filtered, now)
		rateLimitStore.users[userID] = filtered
		rateLimitStore.mu.Unlock()
		return c.Next()
	}
}
