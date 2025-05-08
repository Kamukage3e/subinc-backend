-- Users table for SaaS multi-tenancy
CREATE TABLE
    IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        tenant_id UUID REFERENCES tenants (id) ON DELETE CASCADE,
        email TEXT NOT NULL,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        is_verified BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        metadata JSONB NOT NULL DEFAULT '{}',
        UNIQUE (tenant_id, email),
        UNIQUE (tenant_id, username)
    );

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users (tenant_id);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Make tenant_id nullable if not already
ALTER TABLE users
ALTER COLUMN tenant_id
DROP NOT NULL;