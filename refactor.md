# Refactor Plan: DB-Backed Runtime Config & Feature Toggling

- [x] Remove all config file (YAML) and direct env var loading for runtime config (except DB bootstrap)
- [x] Bootstrap owner DB connection from a single env var (e.g., OWNER_DB_DSN)
- [x] Refactor main.go to load all runtime/config values from the server_config table using server_config.Service
- [x] Use GetOwner*Config methods to load DB, logging, JWT, OAuth, SAML, and other configs
- [x] Remove loadOwnerConfig, os.Getenv("OWNER_CONFIG_PATH"), and all related logic from main.go
- [x] Remove all struct definitions for file-based config in main.go
- [x] Delete config/config.yaml and all code that loads/parses it
- [x] Ensure both owner-admin and client-admin APIs expose endpoints to enable/disable features at runtime (DB-backed)
- [x] After any config update, validate the new config (e.g., test DB/Redis connection) and return the result in the API response
- [x] Update README/docs to state all config is DB-backed and hot-reloadable, except for initial DB bootstrap
- [ ] (Optional) Provide a migration script or admin endpoint to import existing YAML config into the server_config table 