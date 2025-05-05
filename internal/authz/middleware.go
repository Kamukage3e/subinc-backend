package authz

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// OPAAuthzMiddleware returns a Fiber middleware that enforces OPA authorization.
func OPAAuthzMiddleware(opa *OPAClient, log *logger.Logger, policyPath string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		user, roles, tenant, attributes, err := extractAuthContext(c)
		if err != nil {
			log.Warn("auth context extraction failed", logger.ErrorField(err))
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		action := c.Method()
		resource := c.Path()
		input := OPAInput{
			User:     user,
			Roles:    roles,
			Tenant:   tenant,
			Action:   action,
			Resource: resource,
			Context:  map[string]interface{}{"attributes": attributes},
		}
		result, err := opa.Query(ctx, policyPath, input)
		if err != nil {
			log.Error("OPA query failed", logger.ErrorField(err))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
		}
		if !result.Allow {
			log.Info("OPA denied access", logger.String("user", user), logger.Strings("roles", roles), logger.String("tenant", tenant), logger.String("action", action), logger.String("resource", resource), logger.String("reason", result.Reason))
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
		}
		return c.Next()
	}
}

// extractAuthContext extracts user, roles, tenant, and attributes from JWT/context. Adjust as needed for your claims structure.
func extractAuthContext(c *fiber.Ctx) (user string, roles []string, tenant string, attributes map[string]string, err error) {
	claims, ok := c.Locals("claims").(map[string]interface{})
	if !ok {
		return "", nil, "", nil, fmt.Errorf("missing or invalid claims in context")
	}
	userVal, ok := claims["sub"].(string)
	if !ok || userVal == "" {
		return "", nil, "", nil, fmt.Errorf("missing sub claim")
	}
	user = userVal
	rolesIface, ok := claims["roles"]
	if !ok {
		roles = []string{}
	} else {
		switch v := rolesIface.(type) {
		case []interface{}:
			for _, r := range v {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		case string:
			roles = strings.Split(v, ",")
		}
	}
	tenantVal, ok := claims["tenant_id"].(string)
	if !ok || tenantVal == "" {
		return "", nil, "", nil, fmt.Errorf("missing tenant_id claim")
	}
	tenant = tenantVal
	attributes = map[string]string{}
	if attrsIface, ok := claims["attributes"]; ok {
		switch v := attrsIface.(type) {
		case map[string]interface{}:
			for k, val := range v {
				if s, ok := val.(string); ok {
					attributes[k] = s
				}
			}
		}
	}
	return user, roles, tenant, attributes, nil
}
