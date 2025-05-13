package security_management

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

// SessionAuthMiddleware validates session tokens provided in the Authorization header
func SessionAuthMiddleware(sessionService interface {
	GetSession(ctx context.Context, sessionID string) (Session, error)
}) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid Authorization header"})
		}

		sessionID := strings.TrimPrefix(authHeader, "Bearer ")
		if sessionID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session token required"})
		}

		session, err := sessionService.GetSession(c.Context(), sessionID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid session"})
		}

		// Check if session has expired
		if time.Now().UTC().After(session.ExpiresAt) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session expired"})
		}

		// Set user information in context for handlers to use
		c.Locals("user_id", session.UserID)
		c.Locals("session_id", session.ID)

		return c.Next()
	}
}

// OIDCMiddleware validates JWT/OIDC tokens and sets claims in context.
func OIDCMiddleware(jwtSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid Authorization header"})
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid claims"})
		}
		c.Locals("claims", claims)
		return c.Next()
	}
}

// NewRateLimitMiddleware returns a distributed, DB-backed rate limiter middleware for the given scope extractor.
// scopeExtractor returns (scope, scopeID) for the request (e.g., ("tenant", tenantID)).
func NewRateLimitMiddleware(rateLimitService RateLimitService, scopeExtractor func(*fiber.Ctx) (string, string)) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if rateLimitService == nil {
			return c.Next()
		}
		scope, scopeID := scopeExtractor(c)
		if scope == "" || scopeID == "" {
			return c.Next()
		}
		cfg, err := rateLimitService.GetRateLimit(c.Context(), scope, scopeID)
		if err != nil || cfg.Limit <= 0 || cfg.WindowSeconds <= 0 {
			return c.Next()
		}
		pool, ok := c.Locals("db").(*pgxpool.Pool)
		if !ok || pool == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db unavailable"})
		}
		const upsert = `INSERT INTO rate_limit_counters (scope, scope_id, window_start, count)
			VALUES ($1, $2, NOW(), 1)
			ON CONFLICT (scope, scope_id) DO UPDATE SET
				count = CASE WHEN EXTRACT(EPOCH FROM (NOW() - rate_limit_counters.window_start)) < $3 THEN rate_limit_counters.count + 1 ELSE 1 END,
				window_start = CASE WHEN EXTRACT(EPOCH FROM (NOW() - rate_limit_counters.window_start)) < $3 THEN rate_limit_counters.window_start ELSE NOW() END
			RETURNING count, window_start`
		var count int
		var windowStart time.Time
		err = pool.QueryRow(c.Context(), upsert, scope, scopeID, cfg.WindowSeconds).Scan(&count, &windowStart)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rate limit counter error"})
		}
		if count > cfg.Limit {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "rate limit exceeded"})
		}
		return c.Next()
	}
}
