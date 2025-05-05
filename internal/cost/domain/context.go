package domain

import (
	"context"
)

// Context keys for values stored in context
type ContextKey string

const (
	// TenantIDKey is the key for tenant ID in context
	TenantIDKey ContextKey = "tenant_id"

	// UserIDKey is the key for user ID in context
	UserIDKey ContextKey = "user_id"

	// RolesKey is the key for user roles in context
	RolesKey ContextKey = "roles"

	// TraceIDKey is the key for trace ID in context
	TraceIDKey ContextKey = "trace_id"

	// PermissionsKey is the key for user permissions in context
	PermissionsKey ContextKey = "permissions"
)

// WithTenantID adds tenant ID to context
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// GetTenantID extracts tenant ID from context
func GetTenantID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(TenantIDKey).(string)
	return v, ok
}

// WithUserID adds user ID to context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(UserIDKey).(string)
	return v, ok
}

// WithRoles adds user roles to context
func WithRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, RolesKey, roles)
}

// GetRoles extracts user roles from context
func GetRoles(ctx context.Context) ([]string, bool) {
	v, ok := ctx.Value(RolesKey).([]string)
	return v, ok
}

// WithTraceID adds trace ID to context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// GetTraceID extracts trace ID from context
func GetTraceID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(TraceIDKey).(string)
	return v, ok
}

// WithPermissions adds permissions to context
func WithPermissions(ctx context.Context, permissions []string) context.Context {
	return context.WithValue(ctx, PermissionsKey, permissions)
}

// GetPermissions extracts permissions from context
func GetPermissions(ctx context.Context) ([]string, bool) {
	v, ok := ctx.Value(PermissionsKey).([]string)
	return v, ok
}
