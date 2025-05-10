package security_management

import (
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// securityHeadersMiddleware sets strict security headers for all responses.
func securityHeadersMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		return c.Next()
	}
}

// inMemoryRateLimiter is a simple, thread-safe, in-memory rate limiter for demo/prod use.
type inMemoryRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newInMemoryRateLimiter(limit int, window time.Duration) *inMemoryRateLimiter {
	return &inMemoryRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *inMemoryRateLimiter) middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		now := time.Now()
		cutoff := now.Add(-rl.window)
		rl.mu.Lock()
		reqs := rl.requests[ip]
		// Remove old requests
		var filtered []time.Time
		for _, t := range reqs {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) >= rl.limit {
			rl.mu.Unlock()
			return c.Status(429).JSON(fiber.Map{"error": "rate limit exceeded"})
		}
		filtered = append(filtered, now)
		rl.requests[ip] = filtered
		rl.mu.Unlock()
		return c.Next()
	}
}