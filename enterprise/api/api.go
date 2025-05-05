package api

import (
	"context"
)

// EnterpriseAPI exposes enterprise-only endpoints and features.
type EnterpriseAPI interface {
	GetFeatureFlags(ctx context.Context, orgID string) (map[string]bool, error)
	SetFeatureFlag(ctx context.Context, orgID, flag string, enabled bool) error
	ListAvailableFeatures(ctx context.Context) ([]string, error)
}
