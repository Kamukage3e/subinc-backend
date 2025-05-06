package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/subinc/subinc-backend/internal/admin"
	. "github.com/subinc/subinc-backend/internal/pkg/logger"
)



func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(httpResponseSize)
}

// RequestLogger creates a Fiber middleware for structured request logging with logger.Logger
func RequestLogger(log *Logger, adminStore *admin.PostgresAdminStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Start timer
		start := time.Now()
		path := c.Path()
		method := c.Method()

		// Process request
		var err error
		var statusCode int

		// Create request ID for tracing
		requestID := c.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), c.IP())
			c.Set("X-Request-ID", requestID)
		}

		// Execute next handler
		chainErr := c.Next()

		// Set error and status code
		if chainErr != nil {
			err = chainErr
			statusCode = fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				statusCode = e.Code
			}
		} else {
			statusCode = c.Response().StatusCode()
		}

		// Record metrics
		duration := time.Since(start).Seconds()
		httpRequestsTotal.WithLabelValues(method, path, fmt.Sprintf("%d", statusCode)).Inc()
		httpRequestDuration.WithLabelValues(method, path).Observe(duration)
		httpResponseSize.WithLabelValues(method, path).Observe(float64(len(c.Response().Body())))

		// Skip logging for health check endpoints to reduce noise
		if path == "/healthz" || path == "/healthz/redis" || path == "/healthz/postgres" {
			return err
		}

		// Prepare logging fields
		fields := []Field{
			String("request_id", requestID),
			String("remote_ip", c.IP()),
			String("method", method),
			String("path", path),
			Int("status", statusCode),
			Float64("latency_ms", float64(time.Since(start).Microseconds())/1000.0),
			Int("body_size", len(c.Response().Body())),
			String("user_agent", c.Get("User-Agent")),
		}

		// Add referer if present
		referer := c.Get("Referer")
		if referer != "" {
			fields = append(fields, String("referer", referer))
		}

		// Add error if present
		if err != nil {
			fields = append(fields, ErrorField(err))
		}

		// --- ADMIN API AUDIT LOG ---
		if strings.HasPrefix(path, "/admin/") {
			claims, ok := c.Locals("claims").(map[string]interface{})
			actor := "anonymous"
			if ok {
				if sub, ok := claims["sub"].(string); ok && sub != "" {
					actor = sub
				}
			}
			// Only log if authenticated
			if actor != "anonymous" {
				_ = adminStore.LogAuditEvent(
					"admin_api_audit",
					method,
					actor,
					map[string]interface{}{
						"resource":   path,
						"status":     statusCode,
						"request_id": requestID,
					},
				)
			}
		}
		// --- END ADMIN API AUDIT LOG ---

		// Log with appropriate level based on status code
		switch {
		case statusCode >= 500:
			log.Error("server error", fields...)
		case statusCode >= 400:
			log.Warn("client error", fields...)
		case statusCode >= 300:
			log.Info("redirection", fields...)
		default:
			log.Info("request completed", fields...)
		}

		return err
	}
}
