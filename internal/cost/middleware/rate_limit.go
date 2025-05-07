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

// rateLimitEntry tracks request count and last reset
// Not safe for distributed use; swap for Redis in prod
var rateLimitMu sync.Mutex
var rateLimitMap = make(map[string]*rateLimitEntry)

type rateLimitEntry struct {
	Count     int
	LastReset time.Time
}

const (
	deviceLimit = 10 // max requests per minute per device
	ipLimit     = 20 // max requests per minute per IP
)

var ipBlacklistMu sync.RWMutex
var ipBlacklist = make(map[string]struct{})

// AddIPToBlacklist adds an IP to the blacklist
func AddIPToBlacklist(ip string) {
	ipBlacklistMu.Lock()
	defer ipBlacklistMu.Unlock()
	ipBlacklist[ip] = struct{}{}
}

// RemoveIPFromBlacklist removes an IP from the blacklist
func RemoveIPFromBlacklist(ip string) {
	ipBlacklistMu.Lock()
	defer ipBlacklistMu.Unlock()
	delete(ipBlacklist, ip)
}

// IPBlacklistMiddleware blocks requests from blacklisted IPs
func IPBlacklistMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		ipBlacklistMu.RLock()
		_, blacklisted := ipBlacklist[ip]
		ipBlacklistMu.RUnlock()
		if blacklisted {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden: your IP is blacklisted"})
		}
		return c.Next()
	}
}

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

func RateLimitMiddlewarePerDeviceIP() fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		refreshToken := c.Cookies("refresh_token")
		keyDevice := "dev:" + refreshToken
		keyIP := "ip:" + ip
		rateLimitMu.Lock()
		defer rateLimitMu.Unlock()
		now := time.Now()
		resetIfNeeded := func(key string, limit int) bool {
			e, ok := rateLimitMap[key]
			if !ok || now.Sub(e.LastReset) > time.Minute {
				rateLimitMap[key] = &rateLimitEntry{Count: 1, LastReset: now}
				return true
			}
			if e.Count >= limit {
				return false
			}
			e.Count++
			return true
		}
		if refreshToken != "" && !resetIfNeeded(keyDevice, deviceLimit) {
			return c.Status(429).JSON(fiber.Map{"error": "rate limit exceeded for device"})
		}
		if !resetIfNeeded(keyIP, ipLimit) {
			return c.Status(429).JSON(fiber.Map{"error": "rate limit exceeded for IP"})
		}
		return c.Next()
	}
}
