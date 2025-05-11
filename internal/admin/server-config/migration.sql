-- Server config table for runtime, DB-backed, hot-reloadable server-side configuration
CREATE TABLE
    IF NOT EXISTS server_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        version INT NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
    );

-- Audit/versioning table for server config changes
CREATE TABLE
    IF NOT EXISTS server_config_history (
        id SERIAL PRIMARY KEY,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        version INT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        updated_by TEXT NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_server_config_history_key ON server_config_history (key);