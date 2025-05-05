CREATE TABLE IF NOT EXISTS cloud_credentials (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    credentials TEXT NOT NULL,
    default_account TEXT,
    account_list TEXT[],
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_validated_at TIMESTAMPTZ,
    is_valid BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_cloud_credentials_tenant_id ON cloud_credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_provider ON cloud_credentials(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_name ON cloud_credentials(name); 