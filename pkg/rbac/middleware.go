package rbac

import (
	"context"
	"net/http"
	"regexp"

	"github.com/gofiber/fiber/v2"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	"github.com/subinc/subinc-backend/internal/pkg/interfaces"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Config holds RBAC middleware config
// Enable: toggles RBAC enforcement
// RBACService: the RBAC service to use
// SessionManager: session manager for extracting user info
// ResourceResolver: function to resolve resource/action from request
// RoutePermissionMapping: maps routes to permissions for centralized control
// ValidateJWT: whether to validate JWT tokens instead of sessions
// AllowedPatterns: regex patterns for paths that should bypass RBAC
// DefaultDenyUnmapped: if true, endpoints not in the mapping are denied by default
//
// All fields must be set for production use.
type Config struct {
	Enable              bool
	RBACService         rbac_management.RBACService
	SessionManager      interfaces.SessionService
	ResourceResolver    func(*fiber.Ctx) (resource, action string, err error)
	RoutePermissionMap  map[string]map[string]Permission // Method -> Path -> Permission
	ValidateJWT         bool
	AllowedPatterns     []*regexp.Regexp
	DefaultDenyUnmapped bool // If true, endpoints not in the mapping are denied by default
}

// Permission represents a resource and action required for an endpoint
type Permission struct {
	Resource string
	Action   string
}

// Middleware returns a Fiber middleware enforcing RBAC if enabled.
func Middleware(cfg Config) fiber.Handler {
	if !cfg.Enable {
		return func(c *fiber.Ctx) error { return c.Next() }
	}

	// Validate configuration
	if cfg.RBACService == nil || cfg.SessionManager == nil || (cfg.ResourceResolver == nil && cfg.RoutePermissionMap == nil) {
		// Log error instead of panic
		logger.LogError(
			"RBAC middleware misconfigured",
			logger.Bool("rbac_service_nil", cfg.RBACService == nil),
			logger.Bool("session_manager_nil", cfg.SessionManager == nil),
			logger.Bool("resource_resolver_nil", cfg.ResourceResolver == nil),
			logger.Bool("route_permission_map_nil", cfg.RoutePermissionMap == nil),
		)

		// Return a middleware that always returns an error
		return func(c *fiber.Ctx) error {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error": "server configuration error: RBAC middleware misconfigured",
			})
		}
	}

	return func(c *fiber.Ctx) error {
		// Check for bypass patterns first
		if cfg.AllowedPatterns != nil {
			path := c.Path()
			for _, pattern := range cfg.AllowedPatterns {
				if pattern.MatchString(path) {
					return c.Next()
				}
			}
		}

		sessionID := c.Cookies("session_id")
		if sessionID == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session_id cookie required"})
		}

		sess, err := cfg.SessionManager.GetSession(c.Context(), sessionID)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: invalid or expired session"})
		}

		userID := sess.UserID
		if userID == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: user required"})
		}

		var resource, action string

		// Try to resolve resource/action from RoutePermissionMap first
		if cfg.RoutePermissionMap != nil {
			method := c.Method()
			path := c.Path()

			if methodMap, ok := cfg.RoutePermissionMap[method]; ok {
				if permission, ok := methodMap[path]; ok {
					resource = permission.Resource
					action = permission.Action
				}
			}
		}

		// If not found in map and ResourceResolver provided, use it as fallback
		if resource == "" && action == "" && cfg.ResourceResolver != nil {
			var err error
			resource, action, err = cfg.ResourceResolver(c)
			if err != nil {
				return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid resource/action: "})
			}
		}

		// If still not resolved and default deny is enabled, reject
		if (resource == "" || action == "") && cfg.DefaultDenyUnmapped {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: route not mapped to permission"})
		}

		// Check permission
		allowed, err := cfg.RBACService.CheckAccess(context.Background(), userID, resource, action, nil)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "rbac check failed"})
		}
		if !allowed {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden: insufficient permissions"})
		}
		return c.Next()
	}
}

// CreateRouteResourceResolver creates a new resource resolver based on route mappings
// This is useful when you want to automatically derive resources/actions from routes
func CreateRouteResourceResolver(routeMap map[string]map[string]Permission) func(*fiber.Ctx) (string, string, error) {
	return func(c *fiber.Ctx) (string, string, error) {
		method := c.Method()
		path := c.Path()

		if methodMap, ok := routeMap[method]; ok {
			if permission, ok := methodMap[path]; ok {
				return permission.Resource, permission.Action, nil
			}
		}

		// Default resource/action based on path and method when not explicitly mapped
		resource := path
		action := method
		return resource, action, nil
	}
}
