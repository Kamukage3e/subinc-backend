-- Create schema_migrations table for golang-migrate compatibility
CREATE TABLE
    IF NOT EXISTS schema_migrations (
        version bigint not null primary key,
        dirty boolean not null
    );

-- Tenants table for SaaS multi-tenancy
CREATE TABLE
    IF NOT EXISTS tenants (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX IF NOT EXISTS idx_tenants_email ON tenants (email);