CREATE TABLE IF NOT EXISTS cloud_credentials (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    credentials TEXT NOT NULL,
    default_account TEXT,
    account_list TEXT[],
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_validated_at TIMESTAMPTZ,
    is_valid BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT cloud_credentials_tenant_provider_name_unique UNIQUE (tenant_id, provider, name)
);

CREATE INDEX idx_cloud_credentials_tenant_id ON cloud_credentials(tenant_id);
CREATE INDEX idx_cloud_credentials_provider ON cloud_credentials(provider);
CREATE INDEX idx_cloud_credentials_name ON cloud_credentials(name); 