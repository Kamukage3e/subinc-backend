package billing_management

import (
	"context"
)

// GetTenantIDFromContext safely extracts the tenant ID from context
// This is a utility function used across all billing components to ensure
// consistent tenant ID extraction for isolation
func GetTenantIDFromContext(ctx context.Context) string {
	// Try to get from context value (set by middleware)
	if v := ctx.Value("tenant_id"); v != nil {
		if tid, ok := v.(string); ok && tid != "" {
			return tid
		}
	}
	return ""
}

// AddTenantIDToQuery adds tenant ID filtering to a SQL query if available in context
// Returns the modified query and the tenant ID parameter to be added to args
func AddTenantIDToQuery(ctx context.Context, query string, whereClause bool) (string, string) {
	tenantID := GetTenantIDFromContext(ctx)
	if tenantID == "" {
		return query, ""
	}

	// If whereClause is true, we need to add a WHERE clause
	// Otherwise, we assume the WHERE clause exists and add AND tenant_id = $X
	if whereClause {
		return query + " WHERE tenant_id = $1", tenantID
	}

	// Add AND condition
	return query + " AND tenant_id = $1", tenantID
}

// GetAccountIDFromContext extracts the account ID from context if available
func GetAccountIDFromContext(ctx context.Context) string {
	// Try to get from context value (set by middleware)
	if v := ctx.Value("account_id"); v != nil {
		if aid, ok := v.(string); ok && aid != "" {
			return aid
		}
	}
	return ""
}

// GetInvoiceIDFromContext extracts the invoice ID from context if available
func GetInvoiceIDFromContext(ctx context.Context) string {
	// Try to get from context value (set by middleware)
	if v := ctx.Value("invoice_id"); v != nil {
		if iid, ok := v.(string); ok && iid != "" {
			return iid
		}
	}
	return ""
}
