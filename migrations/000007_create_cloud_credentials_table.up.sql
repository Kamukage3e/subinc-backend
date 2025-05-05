CREATE TABLE IF NOT EXISTS cloud_credentials (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    encrypted_credentials TEXT NOT NULL,
    default_account VARCHAR(255),
    account_list TEXT[],
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_validated_at TIMESTAMP WITH TIME ZONE,
    is_valid BOOLEAN NOT NULL DEFAULT FALSE,
    
    CONSTRAINT cloud_credentials_tenant_provider_name_unique UNIQUE (tenant_id, provider, name)
);

-- Add indexes for common query patterns
CREATE INDEX idx_cloud_credentials_tenant_id ON cloud_credentials(tenant_id);
CREATE INDEX idx_cloud_credentials_tenant_provider ON cloud_credentials(tenant_id, provider);

-- Add comments for documentation
COMMENT ON TABLE cloud_credentials IS 'Stores encrypted cloud provider credentials for tenants';
COMMENT ON COLUMN cloud_credentials.id IS 'Unique identifier for the credential';
COMMENT ON COLUMN cloud_credentials.tenant_id IS 'Tenant ID that owns this credential';
COMMENT ON COLUMN cloud_credentials.provider IS 'Cloud provider type (AWS, Azure, GCP)';
COMMENT ON COLUMN cloud_credentials.name IS 'Human-readable name for the credential';
COMMENT ON COLUMN cloud_credentials.encrypted_credentials IS 'Encrypted credential data (JSON map)';
COMMENT ON COLUMN cloud_credentials.default_account IS 'Default account/subscription/project ID';
COMMENT ON COLUMN cloud_credentials.account_list IS 'List of available accounts/subscriptions/projects';
COMMENT ON COLUMN cloud_credentials.created_at IS 'Time when the credential was created';
COMMENT ON COLUMN cloud_credentials.updated_at IS 'Time when the credential was last updated';
COMMENT ON COLUMN cloud_credentials.last_validated_at IS 'Time when the credential was last validated';
COMMENT ON COLUMN cloud_credentials.is_valid IS 'Whether the credential is currently valid'; 