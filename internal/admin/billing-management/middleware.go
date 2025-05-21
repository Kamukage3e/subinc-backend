package billing_management

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// AccountIsolationMiddleware enforces tenant and account isolation for all billing features
// It ensures that operations can only be performed on accounts within the user's authorized tenant
func AccountIsolationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract tenant ID from header or locals
		tenantID := c.Get("X-Tenant-ID")
		if tenantID == "" {
			// Check if it's in locals (set by TenantMiddleware)
			if localTenantID, ok := c.Locals("tenant_id").(string); ok && localTenantID != "" {
				tenantID = localTenantID
			}
		}

		// If no tenant ID is found, require authentication
		if tenantID == "" {
			logger.LogError("AccountIsolationMiddleware: no tenant ID provided")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing tenant ID in X-Tenant-ID header",
				"code":  "TENANT_REQUIRED",
			})
		}

		// Set tenant ID in context for downstream handlers and stores
		c.Context().SetUserValue("tenant_id", tenantID)
		c.Locals("tenant_id", tenantID)

		// Add tenant ID to any existing headers for consistency
		if c.Get("X-Tenant-ID") == "" {
			c.Request().Header.Set("X-Tenant-ID", tenantID)
		}

		// Extract account_id from path parameters
		// This handles routes like /billing-management/accounts/:id
		accountID := c.Params("id")
		if accountID != "" {
			// If we have an account ID in the path, store it for validation by handlers
			c.Locals("account_id", accountID)
			c.Context().SetUserValue("account_id", accountID)
		}

		// Extract invoice_id from path parameters or query
		// This handles routes like /billing-management/invoices/:id
		invoiceID := c.Params("id")
		if invoiceID != "" && strings.Contains(c.Path(), "/invoices/") {
			c.Locals("invoice_id", invoiceID)
			c.Context().SetUserValue("invoice_id", invoiceID)
		}

		// Extract any account_id from query parameters
		// This handles routes like /billing-management/invoices?account_id=xxx
		queryAccountID := c.Query("account_id")
		if queryAccountID != "" {
			c.Locals("query_account_id", queryAccountID)
			c.Context().SetUserValue("query_account_id", queryAccountID)
		}

		// Continue to the next handler
		return c.Next()
	}
}

// ValidateBillingAccountAccess ensures the specified account belongs to the tenant
// It can be used within handlers to verify that an account ID from a request body
// is valid for the current tenant context
func ValidateBillingAccountAccess(ctx fiber.Ctx, accountStore account.BillingAccountService) (bool, error) {
	// Get tenant ID from context
	tenantID, ok := ctx.Locals("tenant_id").(string)
	if !ok || tenantID == "" {
		return false, fiber.NewError(fiber.StatusBadRequest, "Missing tenant context")
	}

	// Get account ID to validate
	accountID, ok := ctx.Locals("account_id").(string)
	if !ok || accountID == "" {
		// Check if we have a query account ID
		accountID, ok = ctx.Locals("query_account_id").(string)
		if !ok || accountID == "" {
			// No account ID to validate
			return true, nil
		}
	}

	// Query the account to verify tenant - try each account type
	acct, err := accountStore.Get(ctx.Context(), account.AccountTypeProject, accountID)
	if err != nil {
		// Try with user account type
		acct, err = accountStore.Get(ctx.Context(), account.AccountTypeUser, accountID)
		if err != nil {
			// Try with organization account type
			acct, err = accountStore.Get(ctx.Context(), account.AccountTypeOrganization, accountID)
			if err != nil {
				logger.LogError("ValidateBillingAccountAccess: account not found",
					logger.String("account_id", accountID),
					logger.ErrorField(err))
				return false, fiber.NewError(fiber.StatusNotFound, "Account not found")
			}
		}
	}

	// Verify tenant ID matches - extract tenant ID from account based on type
	var accountTenantID string

	// Extract tenant ID based on the account type
	switch a := acct.(type) {
	case *account.ProjectBillingAccount:
		accountTenantID = a.TenantID
	case *account.UserBillingAccount:
		accountTenantID = a.TenantID
	case *account.OrganizationBillingAccount:
		accountTenantID = a.TenantID
	case map[string]interface{}:
		if tid, ok := a["tenant_id"].(string); ok {
			accountTenantID = tid
		}
	}

	if accountTenantID != tenantID {
		logger.LogError("ValidateBillingAccountAccess: tenant mismatch",
			logger.String("account_id", accountID),
			logger.String("account_tenant", accountTenantID),
			logger.String("request_tenant", tenantID))
		return false, fiber.NewError(fiber.StatusForbidden, "Access denied to account in different tenant")
	}

	return true, nil
}
