-- Users table for SaaS multi-tenancy
CREATE TABLE
    users (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
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

CREATE INDEX idx_users_tenant_id ON users (tenant_id);

CREATE INDEX idx_users_email ON users (email);