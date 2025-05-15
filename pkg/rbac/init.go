package rbac

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/pkg/session"
)

// DefaultReloadInterval is the default interval for reloading RBAC config
const DefaultReloadInterval = 30 * time.Second

// InitializeRBAC sets up and returns a new RBAC configurator
// It also starts the config reloader to watch for changes in RBAC settings
func InitializeRBAC(
	rbacService rbac_management.RBACService,
	sessionManager *session.SessionManager,
	configService *server_config.Service,
	reloadInterval time.Duration,
) *RBACConfigurator {
	if reloadInterval == 0 {
		reloadInterval = DefaultReloadInterval
	}

	rc := NewRBACConfigurator(
		rbacService,
		sessionManager,
		configService,
		reloadInterval,
	)

	// Start the config reloader in background
	rc.StartConfigReloader(context.Background())

	return rc
}

// ApplyRBACMiddleware applies RBAC middleware to a Fiber router
// with the given RBAC configurator. This is a convenience function
// for applying RBAC to a router or router group.
func ApplyRBACMiddleware(router fiber.Router, configurator *RBACConfigurator) {
	router.Use(configurator.Middleware())
}

// SetupCommonBypassPatterns adds common bypass patterns to the RBAC configurator
// that typically should not be protected by RBAC (like health checks, static files,
// login endpoints, etc.)
func SetupCommonBypassPatterns(configurator *RBACConfigurator) error {
	patterns := []string{
		`^/health$`,               // Health check
		`^/metrics$`,              // Metrics endpoint
		`^/api/v1/auth/login$`,    // Login endpoint
		`^/api/v1/auth/logout$`,   // Logout endpoint
		`^/api/v1/auth/register$`, // Register endpoint
		`^/api/v1/bootstrap/`,     // Bootstrap endpoints
		`^/swagger\.`,             // Swagger endpoints
		`^/docs/`,                 // Docs endpoints
		`^/static/`,               // Static files
	}

	for _, pattern := range patterns {
		if err := configurator.AddBypassPattern(pattern); err != nil {
			return err
		}
	}

	return nil
}
