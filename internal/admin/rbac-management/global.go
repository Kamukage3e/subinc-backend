package rbac_management

import (
	"sync"
)

var (
	globalRBACStore     *PostgresStore
	globalRBACStoreOnce sync.Once
)

// InitGlobalRBACStore must be called once at app startup with the canonical DB and AuditLogger.
func InitGlobalRBACStore(store *PostgresStore) {
	globalRBACStoreOnce.Do(func() {
		globalRBACStore = store
	})
}

// GlobalRBACStore returns the singleton RBAC store. Panics if not initialized.
func GlobalRBACStore() *PostgresStore {
	if globalRBACStore == nil {
		panic("GlobalRBACStore not initialized")
	}
	return globalRBACStore
}
