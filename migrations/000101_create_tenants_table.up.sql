CREATE TABLE
    tenants (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        settings TEXT NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX idx_tenants_name ON tenants (name);