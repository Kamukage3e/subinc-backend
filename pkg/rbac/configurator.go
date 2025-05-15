package rbac

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/pkg/session"
)

// RBACConfigurator provides a centralized way to configure RBAC
// It supports hot-reloading of RBAC settings and route mappings
// from the server config database, allowing runtime enabling/disabling
// of RBAC enforcement.
type RBACConfigurator struct {
	rbacCfg            Config
	configService      *server_config.Service
	routeMap           map[string]map[string]Permission
	routeMapMutex      sync.RWMutex
	reloadInterval     time.Duration
	lastReload         time.Time
	stopReload         chan struct{}
	isRBACEnabled      bool
	isReloadingStarted bool
}

// NewRBACConfigurator creates a new RBAC configurator
// It initializes the RBAC config and starts a background reloader
// that periodically loads the latest RBAC settings from the server config DB.
func NewRBACConfigurator(
	rbacService rbac_management.RBACService,
	sessionManager *session.SessionManager,
	configService *server_config.Service,
	reloadInterval time.Duration,
) *RBACConfigurator {
	rc := &RBACConfigurator{
		configService:  configService,
		routeMap:       make(map[string]map[string]Permission),
		reloadInterval: reloadInterval,
		stopReload:     make(chan struct{}),
		rbacCfg: Config{
			Enable:              false, // Disabled by default until loaded from config
			RBACService:         rbacService,
			SessionManager:      sessionManager,
			RoutePermissionMap:  make(map[string]map[string]Permission),
			AllowedPatterns:     make([]*regexp.Regexp, 0),
			DefaultDenyUnmapped: false, // Conservative default
		},
	}

	rc.rbacCfg.ResourceResolver = CreateRouteResourceResolver(rc.routeMap)
	return rc
}

// StartConfigReloader starts a background goroutine that periodically
// reloads RBAC configuration from the server config database.
// This enables runtime control of RBAC settings.
func (rc *RBACConfigurator) StartConfigReloader(ctx context.Context) {
	if rc.isReloadingStarted {
		return
	}
	rc.isReloadingStarted = true

	// Load initial configuration
	if err := rc.reloadConfig(ctx); err != nil {
		// Log error but continue - we'll retry on next interval
	}

	go func() {
		ticker := time.NewTicker(rc.reloadInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := rc.reloadConfig(ctx); err != nil {
					// Log error but continue
				}
			case <-rc.stopReload:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// StopConfigReloader stops the background reloader
func (rc *RBACConfigurator) StopConfigReloader() {
	if rc.isReloadingStarted {
		close(rc.stopReload)
		rc.isReloadingStarted = false
	}
}

// reloadConfig loads the latest RBAC settings from the server config DB
func (rc *RBACConfigurator) reloadConfig(ctx context.Context) error {
	// Load owner RBAC config from server-config
	ownerRBACConfig, err := rc.configService.GetOwnerRBACConfig(ctx)
	if err != nil {
		return err
	}

	rc.routeMapMutex.Lock()
	defer rc.routeMapMutex.Unlock()

	// Update the RBAC enabled flag
	rc.isRBACEnabled = ownerRBACConfig.Enabled
	rc.rbacCfg.Enable = ownerRBACConfig.Enabled

	// Update other settings
	rc.rbacCfg.DefaultDenyUnmapped = ownerRBACConfig.DefaultDenyUnmapped

	// Update bypass patterns
	rc.rbacCfg.AllowedPatterns = make([]*regexp.Regexp, 0, len(ownerRBACConfig.BypassPatterns))
	for _, pattern := range ownerRBACConfig.BypassPatterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			rc.rbacCfg.AllowedPatterns = append(rc.rbacCfg.AllowedPatterns, compiled)
		}
		// Skip invalid patterns but log them
	}

	// Update route permissions
	routeMap := make(map[string]map[string]Permission)
	for _, perm := range ownerRBACConfig.RoutePermissions {
		if _, ok := routeMap[perm.Method]; !ok {
			routeMap[perm.Method] = make(map[string]Permission)
		}

		routeMap[perm.Method][perm.Path] = Permission{
			Resource: perm.Resource,
			Action:   perm.Action,
		}
	}

	// Update the route map and middleware config
	rc.routeMap = routeMap
	rc.rbacCfg.RoutePermissionMap = routeMap

	// Update last reload timestamp
	rc.lastReload = time.Now()
	return nil
}

// IsEnabled returns whether RBAC is currently enabled
func (rc *RBACConfigurator) IsEnabled() bool {
	rc.routeMapMutex.RLock()
	defer rc.routeMapMutex.RUnlock()
	return rc.isRBACEnabled
}

// Middleware returns the current RBAC middleware with the latest config
func (rc *RBACConfigurator) Middleware() fiber.Handler {
	rc.routeMapMutex.RLock()
	cfg := rc.rbacCfg
	rc.routeMapMutex.RUnlock()
	return Middleware(cfg)
}

// AddRoutePermission adds a permission mapping for a specific route
func (rc *RBACConfigurator) AddRoutePermission(method, path, resource, action string) {
	rc.routeMapMutex.Lock()
	defer rc.routeMapMutex.Unlock()

	if _, ok := rc.routeMap[method]; !ok {
		rc.routeMap[method] = make(map[string]Permission)
	}

	rc.routeMap[method][path] = Permission{
		Resource: resource,
		Action:   action,
	}

	// Update the middleware config to use the latest route map
	rc.rbacCfg.RoutePermissionMap = rc.routeMap
}

// AddRoutePermissionBulk adds multiple permission mappings at once
func (rc *RBACConfigurator) AddRoutePermissionBulk(mappings map[string]map[string]Permission) {
	rc.routeMapMutex.Lock()
	defer rc.routeMapMutex.Unlock()

	// Merge the new mappings with existing ones
	for method, paths := range mappings {
		if _, ok := rc.routeMap[method]; !ok {
			rc.routeMap[method] = make(map[string]Permission)
		}

		for path, perm := range paths {
			rc.routeMap[method][path] = perm
		}
	}

	// Update the middleware config
	rc.rbacCfg.RoutePermissionMap = rc.routeMap
}

// AddBypassPattern adds a regex pattern for paths that should bypass RBAC
func (rc *RBACConfigurator) AddBypassPattern(pattern string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	rc.routeMapMutex.Lock()
	defer rc.routeMapMutex.Unlock()

	rc.rbacCfg.AllowedPatterns = append(rc.rbacCfg.AllowedPatterns, compiled)
	return nil
}

// SetDefaultDenyUnmapped sets whether unmapped routes should be denied by default
func (rc *RBACConfigurator) SetDefaultDenyUnmapped(deny bool) {
	rc.routeMapMutex.Lock()
	defer rc.routeMapMutex.Unlock()

	rc.rbacCfg.DefaultDenyUnmapped = deny
}

// Config returns a copy of the current RBAC config
func (rc *RBACConfigurator) Config() Config {
	rc.routeMapMutex.RLock()
	defer rc.routeMapMutex.RUnlock()

	return rc.rbacCfg
}
