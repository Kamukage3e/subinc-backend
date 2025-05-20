package rbac_management

import (
	"fmt"
	"sync"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

var (
	globalRBACStore RBACService
	initOnce        sync.Once
)

// InitGlobalRBACStore initializes the global RBAC store
func InitGlobalRBACStore(store RBACService) {
	initOnce.Do(func() {
		globalRBACStore = store
	})

	// Initialize predefined role templates
	if store != nil {
		if err := store.InitPredefinedRoleTemplates(); err != nil {
			logger.LogError("Failed to initialize predefined role templates", logger.ErrorField(err))
		} else {
			logger.LogInfo("Initialized predefined role templates for billing system")
		}
	}
}

// GetGlobalRBACStore returns the global RBAC store
func GetGlobalRBACStore() (RBACService, error) {
	if globalRBACStore == nil {
		err := fmt.Errorf("GlobalRBACStore not initialized")
		logger.LogError("GetGlobalRBACStore", logger.ErrorField(err))
		return nil, err
	}
	return globalRBACStore, nil
}
